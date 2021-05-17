#include "pin.H"
#include <iostream>
#include <fstream>
#include <execinfo.h>
#include <sys/syscall.h>
#include <sys/types.h>

#define BACKTRACE_SIZE 128
#define BACKTRACE_DEPTH 64

/* maybe ARRAY_SIZE() is way better than this? */
#define WHITELIST_MAGIC 0xCAFE

#define NR_HOTPATH_CANDIDATE 20

/* each candidate have `NR_SYSCALL_PER_CAND` of syscalls stored at most */
#define NR_SYSCALL_PER_CAND 20

/* each syscall can at most have `NR_PTR_ARG` of pointer parameters */
#define NR_PTR_ARG 6

#define OUTPUT_FILENAME "hotpathFinder.out" /* TODO: add knob for this */

std::ofstream outFile;

KNOB<BOOL> KnobThreading(KNOB_MODE_WRITEONCE, "pintool", "mt", "0",
           "whether the target app. is a threading application");
KNOB<BOOL> KnobRetvalChecking(KNOB_MODE_WRITEONCE, "pintool", "retval", "0",
        "whether the syscall retval checking is enabled (disabled if not "
        "specified)");

/*
 * TODO: all of the global vars should be malloc-ed, since PIN doesn't free
 * them up on detach.
 * https://software.intel.com/sites/landingpage/pintool/docs/98314/Pin/html/
 * group__PIN__CONTROL.html#ga6277d16bf33ede39685a26a92fc3cbef
 */

/*
 * there may exist syscalls that we don't want to batch, hence one should add
 * interested syscall to the whitelist, and add its ptr argument (if any) to
 * the second prune stage accordingly.
 *
 * TODO: make related operations for adding syscall smarter. Currently, one
 * would require to update this list, `chkMemRefBySyscall` and `addMemRefTarget`
 * manually in order to add new syscall.
 */
static const UINT16 whitelistedSyscall[] = {
    __NR_epoll_wait,
    __NR_accept4,
    __NR_recvfrom,
    __NR_stat,
    __NR_openat,
    __NR_fstat,
    __NR_writev,
    //__NR_sendfile, batching this would cause bad perf.
    __NR_close,
    __NR_epoll_ctl,
    __NR_setsockopt,
    WHITELIST_MAGIC /* door keeper */
};

struct candidateInfo {
    /*
     * location of first syscall of the candidate in the `head` of `struct
     * backtraceInfo`
     */
    int cLoc;

    /* number of syscalls the span covered starting from `cLoc` */
    int cSpan;

    int curIdx; /* for indexing member `ptrArgBuf`, `nrPtr` and `memRefCnt` */

    /* 
     * number of memory references occurred in the span of specific syscall. note
     * that it's possible that we get negative `memRefCnt` if there has no
     * references occurred except upon syscall entry (i.e. the syscall arg is
     * also the arg of the previous syscalls of this candidate). Hence, any
     * syscall has `memRefCnt` <= 0 is suitable for batching in terms of whether
     * the syscall has pointer dependency issue.
     */
    int memRefCnt[NR_SYSCALL_PER_CAND];

    /* number of ptrs specific syscall has (for indexing `ptrArgBuf`) */
    int nrPtr[NR_SYSCALL_PER_CAND];

    /* ptr args of syscalls of this candidate */
    ADDRINT ptrArgBuf[NR_SYSCALL_PER_CAND][NR_PTR_ARG];

    /* whether the candidate has enough syscalls (>1) for batching */
    bool isBatchable;

#define curCand hc.candInfo[hc.curIdx]

/*
 * increment `curCand.curIdx`. If arrives the tail, increment `hc.curIdx`
 * too.
 *
 * putting this here as it depends to `hc`, which is the same as the macro above.
 */
#define INC_CUR_IDX do { \
                        if (++curCand.curIdx == curCand.cSpan) \
                            hc.curIdx++; \
                    } while (0)
};

/*
 * if the span is greater than 1, we patch those syscalls to batch-ed syscall,
 * since it worth it (at least one user<->kernel round trip saved).
 */
struct hotpathCandidate {
    struct candidateInfo candInfo[NR_HOTPATH_CANDIDATE];
    int nrC; /* # of used candidate (`candInfo`) */
    int curIdx; /* for indexing `candInfo` */
    bool isPruneSecondStageDone;

    /*
     * this flag can be set iff second prune stage is entered, it's used to
     * detect whether retval of specific syscall is saved by application logic.
     * If it's saved, then corresponding refcnt is incremented.
     *
     * the flag is reset once a rax-clobbered instruction is encountered, i.e.
     * the retval is no longer exists in rax.
     */
    bool isRetvalAlive;
};
static struct hotpathCandidate hc = {.nrC = 0,
                                     .curIdx = 0,
                                     .isPruneSecondStageDone = false,
                                     .isRetvalAlive = false,
};

struct backtraceInfo {
    void *head[BACKTRACE_SIZE][BACKTRACE_DEPTH];
    UINT8 nrBacktrace[BACKTRACE_SIZE];
    UINT16 sysnum[BACKTRACE_SIZE];
    int idx; /* for indexing arrays above */

    /*
     * after the hotpath is found (i.e. `isBacktraceExisted()` returns TRUE),
     * the tail (last syscall in the hotpath) would be `idx` - 1.
     */
    int hotpathStart;

    bool isInPruneSecondStage;
    bool isThreadingApp;
    OS_THREAD_ID targetTid;
};

static struct backtraceInfo bt = {.idx = 0,
                                  .isInPruneSecondStage = false,
                                  .isThreadingApp = false,
                                  .targetTid = INVALID_OS_THREAD_ID,
};

static bool isBacktraceExisted(int nr_func)
{
    bool same = true;

    if (!bt.idx)
        return false;

    for (int i = bt.idx - 1; i >= 0; i--) {
        for (int x = 0; x < nr_func; x++) {
            if (bt.head[bt.idx][x] != bt.head[i][x]) {
                same = false;
                break;
            }
        }
        if (same) {
            /*
             * at least CRT has such scenario which has continuous duplicated
             * backtrace. Moreover, it's meanless for batching if the hotpath
             * contains only 1 syscall. Hence ignore this, and keep seeking.
             */
            if (bt.idx - i == 1)
                continue;

            bt.hotpathStart = i;
            return true;
        }
        same = true;
    }

    return false;
}

static void dumpHotpath(void)
{
    if (hc.isPruneSecondStageDone) {
        char **head;
        PIN_LockClient(); /* required by backtrace_symbols() */
        outFile << "\nAfter pruning, we got " << hc.nrC
                << " candidate(s) for doing syscall batching:\n\n";
        for (int i = 0; i < hc.nrC; i++) {
            if (!hc.candInfo[i].isBatchable) {
                outFile << "candidate #" << i << " has too few syscalls for "
                        << "batching.\n\n";
                continue;
            }
            outFile << "candidate #" << i << " contains "
                    << hc.candInfo[i].cSpan << " syscalls.\n\n";
            for (int x = 0; x < hc.candInfo[i].cSpan; x++) {
                int sysIdx = hc.candInfo[i].cLoc + x;
                outFile << "syscall #" << x << " has backtrace:\n";
                head = backtrace_symbols(&bt.head[sysIdx][0],
                                     bt.nrBacktrace[sysIdx]);
                for (int z = 0; z < bt.nrBacktrace[sysIdx]; z++)
                    outFile << bt.head[sysIdx][z] << " --> " << head[z] << "\n";
                outFile << "\n";
                free(head);
            }
        }
        PIN_UnlockClient();
    } else
        outFile << "\nThere are totally " << bt.idx - bt.hotpathStart << " syscalls found within the hotpath.\n";
}

static inline bool isSyscallBlacklisted(UINT16 sysnum)
{
    for (int i = 0; whitelistedSyscall[i] != WHITELIST_MAGIC; i++) {
        if (whitelistedSyscall[i] == sysnum)
            return false;
    }
    return true;
}

/* filter out blacklist-ed syscalls within the hotpath */
static void pruneFirstStage(void)
{
    int pivot = bt.hotpathStart;
    outFile << "First stage prune (filter out syscalls that don't exist in the "
         << "whitelist):\n";
    for (int i = bt.hotpathStart; i < bt.idx; i++) {
        if (isSyscallBlacklisted(bt.sysnum[i])) { /* do prune */
            if (i == pivot) {
                /*
                 * pivot is standing upon blacklisted syscall, move one step
                 * forward
                 */
                pivot = i + 1;
                continue;
            }
            hc.candInfo[hc.nrC].cLoc = pivot;
            hc.candInfo[hc.nrC].cSpan = i - pivot;
            hc.candInfo[hc.nrC].isBatchable = true;
            if (NR_SYSCALL_PER_CAND < hc.candInfo[hc.nrC].cSpan) {
                outFile << "Fatal: hotpath candidate stores too many syscalls. #: "
                     << hc.candInfo[hc.nrC].cSpan << "\n";
                PIN_ExitProcess(-1);
            }
            outFile << "cand. #" << hc.nrC << " has cLoc: " << hc.candInfo[hc.nrC].cLoc << ", cSpan: " <<
                    hc.candInfo[hc.nrC].cSpan << "\n";
            hc.nrC++;
            pivot = i + 1;

            if (hc.nrC == NR_HOTPATH_CANDIDATE) {
                outFile << "Warn: hotpath candidate buffer fulled, syscalls in the"
                     << " hotpath would not be patched\n";
                return;
            }
        }
    }
    /*
     * ensure that pivot didn't update at last syscall of the hotpath, i.e.
     * outside of the hotpath
     */
    if (pivot != bt.idx) {
        hc.candInfo[hc.nrC].isBatchable = true;
        hc.candInfo[hc.nrC].cLoc = pivot;
        hc.candInfo[hc.nrC].cSpan = bt.idx - pivot;
        if (NR_SYSCALL_PER_CAND < hc.candInfo[hc.nrC].cSpan) {
            outFile << "Fatal: hotpath candidate stores too many syscalls. #: "
                 << hc.candInfo[hc.nrC].cSpan << "\n";
            PIN_ExitProcess(-1);
        }
        outFile << "cand. #" << hc.nrC << " has cLoc: " << hc.candInfo[hc.nrC].cLoc << ", cSpan: " <<
                    hc.candInfo[hc.nrC].cSpan << "\n";
        hc.nrC++;
    }
    outFile << "\n";
}

/*
 * add syscalls that have ptr as param to the tracking list. If the syscall used
 * by your target application hasn't added yet, you should add it manually. As
 * existing syscalls does, to add syscall, one need to:
 * 1. specify how many ptr params the syscall has.
 * 2. specify the order of the param (starting from zero).
 * 3. place macro `INC_CUR_IDX` at the end of the case (regardless of whether
 *    the syscall has ptr param).
 * 4. remember to `break` the case
 *
 * note that the check of last syscall of the hotpath is intentionally ignored,
 * since the syscall is going to be executed immediately
 */
static void addMemRefTarget(CONTEXT *ctxt, SYSCALL_STANDARD std)
{
    ADDRINT sysNum = PIN_GetSyscallNumber(ctxt, std);

    /*
     * check if the syscall sequence is correct, if not, we simply reset the
     * refcnts of specific candidate, since the encountered syscall will not be
     * executed in batch-ed way. Specifically, we shouldn't encounter syscall
     * doesn't lays in the recorded syscall sequence (hotpath), which means that
     * current mechanism recording the hotpath has a deficiency that it's
     * possible that it can't capture all syscalls in the actual hotpath,
     * since it thinks the hotpath is found whenever a duplicated backtrace of
     * syscall is found. This mechanism, at least for Nginx, can't capture the
     * hotpath completely, since Nginx uses event-driven model which has at
     * least two events in the hotpath. This would lead to only one event is
     * captured, which is not optimal.
     */
    if (sysNum != bt.sysnum[curCand.cLoc + curCand.curIdx]) {
        for (int z = 0; z < hc.candInfo[hc.curIdx].curIdx; z++)
            hc.candInfo[hc.curIdx].memRefCnt[z] = 0;
        return;
    }

    // ADDRINT insAddr = bt.head[curCand.cLoc + curCand.curIdx][bt.nrBacktrace[curCand.cLoc + curCand.curIdx] - 1];
    // for aquiring addr of the instruction after calling glibc syscall, we should use PIN XED to get the INS
    // then we can add corresponding check for the reference of the retval.
    // https://stackoverflow.com/questions/30449243/intel-pin-tool-get-instruction-from-address

    switch (sysNum) {
    case __NR_epoll_wait:
        hc.candInfo[hc.curIdx].nrPtr[curCand.curIdx] = 1;
        hc.candInfo[hc.curIdx].ptrArgBuf[curCand.curIdx][0] = PIN_GetSyscallArgument(ctxt, std, 1); /* `events` */
        INC_CUR_IDX;
        break;
    case __NR_accept4:
        hc.candInfo[hc.curIdx].nrPtr[curCand.curIdx] = 2;
        hc.candInfo[hc.curIdx].ptrArgBuf[curCand.curIdx][0] = PIN_GetSyscallArgument(ctxt, std, 1); /* `addr` */
        hc.candInfo[hc.curIdx].ptrArgBuf[curCand.curIdx][1] = PIN_GetSyscallArgument(ctxt, std, 2); /* `addrlen` */
        INC_CUR_IDX;
        break;
    case __NR_recvfrom:
        hc.candInfo[hc.curIdx].nrPtr[curCand.curIdx] = 3;
        hc.candInfo[hc.curIdx].ptrArgBuf[curCand.curIdx][0] = PIN_GetSyscallArgument(ctxt, std, 1); /* `buf` */
        hc.candInfo[hc.curIdx].ptrArgBuf[curCand.curIdx][1] = PIN_GetSyscallArgument(ctxt, std, 4); /* `src_addr` */
        hc.candInfo[hc.curIdx].ptrArgBuf[curCand.curIdx][2] = PIN_GetSyscallArgument(ctxt, std, 5); /* `addrlen` */
        INC_CUR_IDX;
        break;
    case __NR_stat:
        hc.candInfo[hc.curIdx].nrPtr[curCand.curIdx] = 1;
        hc.candInfo[hc.curIdx].ptrArgBuf[curCand.curIdx][0] = PIN_GetSyscallArgument(ctxt, std, 1); /* `statbuf` */
        INC_CUR_IDX;
        break;
    case __NR_openat:
        INC_CUR_IDX;
        break;
    case __NR_fstat:
        hc.candInfo[hc.curIdx].nrPtr[curCand.curIdx] = 1;
        hc.candInfo[hc.curIdx].ptrArgBuf[curCand.curIdx][0] = PIN_GetSyscallArgument(ctxt, std, 1); /* `statbuf` */
        INC_CUR_IDX;
        break;
    case __NR_writev:
        INC_CUR_IDX;
        break;
    case __NR_sendfile:
        hc.candInfo[hc.curIdx].nrPtr[curCand.curIdx] = 1;
        hc.candInfo[hc.curIdx].ptrArgBuf[curCand.curIdx][0] = PIN_GetSyscallArgument(ctxt, std, 2); /* `offset` */
        INC_CUR_IDX;
        break;
    case __NR_close:
        INC_CUR_IDX;
        break;
    case __NR_epoll_ctl:
        /*
         * if I understand correctly, param `event` will not be ref-ed after
         * the call.
         */
        INC_CUR_IDX;
        break;
    case __NR_setsockopt:
        INC_CUR_IDX;
        break;
    }
}

static inline void syscallMemChk(ADDRINT sysArg)
{
    struct candidateInfo *curC = &hc.candInfo[hc.curIdx];

    for (int i = 0; i < curC->curIdx; i++) {
        for (int z = 0; z < curC->nrPtr[i]; z++) {
            if (sysArg == curC->ptrArgBuf[i][z])
                curC->memRefCnt[i]--;
        }
    }
}

/*
 * it is possible that pointer args of previous syscalls in the candidate is the
 * arg of the subsequent syscalls in the same candidate. Given this, when such
 * situation occurs, we decrement the reference counter accordingly to prevent
 * the syscall from being filtered out, since such reference is harmless for
 * syscall batching.
 */
static void chkMemRefBySyscall(CONTEXT *ctxt, SYSCALL_STANDARD std)
{
    ADDRINT sysNum = PIN_GetSyscallNumber(ctxt, std);

    /*
     * do not reset related structures here as the following call of this func
     * would do it for us.
     */
    if (sysNum != bt.sysnum[curCand.cLoc + curCand.curIdx])
        return;

    switch (sysNum) {
    case __NR_epoll_wait:
        syscallMemChk(PIN_GetSyscallArgument(ctxt, std, 1)); /* `events` */
        break;
    case __NR_accept4:
        syscallMemChk(PIN_GetSyscallArgument(ctxt, std, 1)); /* `addr` */
        syscallMemChk(PIN_GetSyscallArgument(ctxt, std, 2)); /* `addrlen` */
        break;
    case __NR_recvfrom:
        syscallMemChk(PIN_GetSyscallArgument(ctxt, std, 1)); /* `buf` */
        syscallMemChk(PIN_GetSyscallArgument(ctxt, std, 4)); /* `src_addr` */
        syscallMemChk(PIN_GetSyscallArgument(ctxt, std, 5)); /* `addrlen` */
        break;
    case __NR_stat:
        syscallMemChk(PIN_GetSyscallArgument(ctxt, std, 1)); /* `statbuf` */
        break;
    case __NR_openat:
        break;
    case __NR_fstat:
        syscallMemChk(PIN_GetSyscallArgument(ctxt, std, 1)); /* `statbuf` */
        break;
    case __NR_writev:
        break;
    case __NR_sendfile:
        syscallMemChk(PIN_GetSyscallArgument(ctxt, std, 2)); /* `offset` */
        break;
    case __NR_close:
        break;
    case __NR_epoll_ctl:
        /*
         * if I understand correctly, param `event` would not be ref-ed after
         * the call.
         */
        INC_CUR_IDX;
        break;
    case __NR_setsockopt:
        INC_CUR_IDX;
        break;
    //case __NR_recvfrom:
    //default:
    }
}

/*
 * our profiling app currently supports only for apps that have all its threads
 * doing same routine.
 *
 * TODO: it's possible to implement per-thread profiling, but waht's the policy
 * for determine which hotpath should we pick? By most-common hotpath? Or should
 * we take all hotpaths into account? Any thoughts?
 */
static inline bool isEnterable(void)
{
    OS_THREAD_ID tid;

    if (bt.isThreadingApp) {
        tid = PIN_GetParentTid();
        //outFile << "enterrrrrrrrred\n" << "\n";
        if (INVALID_OS_THREAD_ID == tid)
           /*
            * main thread shouldn't involves the profiling in threading
            * application, as it's possible that it would incurs unwanted refcnt
            * update, i.e. update occurs outside of the hotpath.
            */
            return false;
        if (INVALID_OS_THREAD_ID != bt.targetTid)
            /*
             * someone has already occupied the sit, give it up to prevent too
             * much checking overhead.
             */
            return false;
        tid = PIN_GetTid();
        PIN_LockClient();
        if (INVALID_OS_THREAD_ID == bt.targetTid)
            bt.targetTid = tid;
        else if (bt.targetTid != tid) {
            PIN_UnlockClient();
            return true;
        }
        PIN_UnlockClient();
    }
    return true;
}

/* TODO: the param threadIndex may helps us dealing with threading application */
static void syscallEntryCb(THREADID threadIndex, CONTEXT *ctxt,
                           SYSCALL_STANDARD std, VOID *v)
{
    if (!isEnterable())
        return;

    if (hc.isPruneSecondStageDone)
        return;

    if (bt.isInPruneSecondStage) {
        /* 
         * this func MUST be placed before `addMemRefTarget()`, as it would do
         * necessary reset which doesn't expect this func to be called
         * afterwards. Specifically, it's possible that this func would get
         * miss-leaded by the syscall number after the reset.
         */
        chkMemRefBySyscall(ctxt, std);
        /*
         * at 2nd prune stage, we filter out syscalls that have its
         * retval/pointer_param referenced before the end of the hotpath. We
         * do this by injecting syscall-specific detection callback.
         */
        addMemRefTarget(ctxt, std);

        /*
         * after syscall returns, this makes related routine to check whether
         * there exists an instruction which reads un-clobbered eax (i.e.
         * syscall retval).
         *
         * the reason why checking syscall retval dependency at the second stage
         * is that the check shares the same refcnt, which is driven by index
         * which only get used at second stage. Thus, this saves additional
         * logic for resetting the index.
         */
        hc.isRetvalAlive = true;

        return;
    }

    PIN_LockClient();
    bt.nrBacktrace[bt.idx] = PIN_Backtrace(ctxt, &bt.head[bt.idx][0], BACKTRACE_DEPTH);
    PIN_UnlockClient();

    bt.sysnum[bt.idx] = PIN_GetSyscallNumber(ctxt, std);

    /* 
     * the if-statement finds out whether the syscall cycle (i.e. hotpath)
     * exists. If there exist a syscall called with exactly the same backtrace
     * as the one which has already in the backtrace buffer, we consider the
     * hotpath is found.
     *
     * However, this technique has a deficiency that a syscall with the
     * same backtrace as the one already stored in the buffer could
     * simply be one of the syscall in the hotpath, which we can further
     * realize by checking whether its upcoming syscalls have the same call
     * sequence as the previous one. If it does, then the hotpath is found,
     * otherwise, we should keep recording upcoming syscalls. Sadly, current
     * impl doesn't keep recording the syscall, it simply go to prune stage
     * instead.
     *
     * TODO: By simply keep recording the backtrace until the backtrace buffer
     * is full, then start inspecting the buffer to find the hotpath, maybe we
     * can solve the above-mentioned problem. Note that we may need a timer to
     * prevent hang up at instrumentation stage (i.e. at hotpath finding stage).
     */
    if (isBacktraceExisted(bt.nrBacktrace[bt.idx])) {
        dumpHotpath();
        pruneFirstStage();
        bt.isInPruneSecondStage = true;

        /*
         * in this context, it's probably the first syscall of the hotpath,
         * thus we start recording possible pointer content. If the context
         * is not of the first syscall, it's ok, we'll realize that by
         * using `hc.curIdx` to check whether the syscall sequence
         * corresponds to the hotpath's one for each upcoming syscall
         */
        addMemRefTarget(ctxt, std);

        hc.isRetvalAlive = true;

        return;
    }

    if ((bt.idx + 1) >= BACKTRACE_SIZE || bt.nrBacktrace[bt.idx] > BACKTRACE_SIZE) {
        outFile << "Fatal: either bt buffer fulled or max nrBacktrace hit\n" << "\n";
        PIN_ExitProcess(-1);
    }
    bt.idx++; // precedence of `++` op within the OR statement?
}

/*
 * filter out syscalls that have refcnt > 0, i.e. amount of the candidate may
 * increases provided that there remains unused candidate entries.
 *
 * TODO: reclaim dropped candidate to utilize the capacity efficiently.
 */
static void pruneSecondStage(void)
{
    outFile << "Second stage prune (filter out syscalls that have refcnt of "
            << "ptr param and syscall retval > 0):\n";
    for (int i = hc.nrC - 1; i >= 0 ; i--) {
        for (int x = hc.candInfo[i].curIdx - 1; x >= 0; x--) {
            if (hc.candInfo[i].memRefCnt[x] > 0) {
                outFile << "cLoc:" << hc.candInfo[i].cLoc + x 
                     << " has memref count of " << hc.candInfo[i].memRefCnt[x]
                     << "\n";
                if ((x + 1) == hc.candInfo[i].curIdx) {
                    /*
                     * check whether this is the TAIL of the candidate. If it is
                     * ,then the splitting result would has syscall less than 2,
                     * which is meanless for batching. Simply drop the syscall.
                     *
                     * for those at/next to the head, no update is required,
                     * since the checking statement below would filter the
                     * candidate out.
                     */
                    hc.candInfo[i].cSpan--;
                    hc.candInfo[i].curIdx--;
                } else if ((x + 2) == hc.candInfo[i].curIdx) {
                    /* same above, but check whether next to the TAIL. */
                    hc.candInfo[i].cSpan -= 2;
                    hc.candInfo[i].curIdx -= 2;
                } else {
                    /* split normal candidate here */
                    if (NR_HOTPATH_CANDIDATE - hc.nrC <= 0) {
                        hc.candInfo[i].isBatchable = false;
                        outFile << "Warn: not enough candidate capacity for"
                             << " splitting, discarding the candidate...\n";
                        break;
                    }
                    /* TODO: add an illustration here for a more specific desc. */
                    /* `+1` to exclude syscall that has dep. issue */
                    hc.candInfo[hc.nrC].cLoc = hc.candInfo[i].cLoc + x + 1;
                    /* `-1` to exclude syscall that has dep. issue */
                    hc.candInfo[hc.nrC].cSpan = hc.candInfo[i].cSpan - x - 1;
                    hc.candInfo[i].cSpan = x;
                    outFile << "new candidate (#" << hc.nrC << ") has cLoc: "
                         << hc.candInfo[hc.nrC].cLoc << ", cSpan: "
                         << hc.candInfo[hc.nrC].cSpan << "\n";
                    /* curIdx should always at last-syscall-in-cand-plus-one-idx after entering the second stage */
                    hc.candInfo[i].curIdx = x + 1;
                    hc.candInfo[hc.nrC].isBatchable = true;
                    hc.nrC++;
                    continue;
                }

                if (hc.candInfo[i].cSpan < 2) {
                    /* too few syscalls after pruning, drop the candidate */
                    hc.candInfo[i].isBatchable = false;
                    break;
                }
            }
        }
    }
}

/*
 * check whether second stage profiling has finished, if it did, start epilog
 * tasks and register for detachment from the application.
 *
 * note that since the detachment doesn't happen synchronously, any
 * instrumentation, analysis or callback routines are possible to get invoked
 * after the detachment has issued. In light of this, if any accident occurs
 * after the hotpath is dumped, one can suspect that it's caused by this.
 * However, I haven't ran into such issue so far. If this indeed happens, the
 * fix would be add some logic to corresponding routines to check whether the
 * tool has entered the epilog stage.
 */
static inline bool isSecondStageProfilingDone(void)
{
    if ((hc.nrC != 0) && (hc.curIdx == hc.nrC)) {
        pruneSecondStage();
        hc.isPruneSecondStageDone = true;
        dumpHotpath();
        outFile << "Detaching from the application..." << std::endl;
        PIN_Detach();
        return true;
    }
    return false;
}

static void memRefDetector(ADDRINT readAddr)
{
    if (!isEnterable())
        return;

    if(isSecondStageProfilingDone())
        return;

    struct candidateInfo *curC = &hc.candInfo[hc.curIdx];

    for (int i = 0; i < curC->curIdx; i++) {
        for (int z = 0; z < curC->nrPtr[i]; z++) {
            if (readAddr == curC->ptrArgBuf[i][z])
                curC->memRefCnt[i]++;
        }
    }
}

/* check whether the retval is saved by application logic, if it does, increment
 * refcnt of corresponding syscall.
 *
 * @isRead indidate instruction triggering this routine is reading or writing
 * EAX register (i.e. syscall retval).
 */
static void retvalRefDetector(bool isRead)
{
    if (!bt.isInPruneSecondStage)
        return;

    if(isSecondStageProfilingDone())
        return;

    if (isRead) {
        if (!hc.isRetvalAlive)
            return; /* syscall retval has been clobbered */

        /*
         * increment refcnt of corresponding syscall in the candidate.
         *
         * it's possible to get negative index
         */
        if (curCand.curIdx - 1 >= 0)
            curCand.memRefCnt[curCand.curIdx - 1]++;
    } else { /* the instruction is a write instruction */
        /* disable the flag as EAX is about to be clobbered */
        hc.isRetvalAlive = false;
    }
}

/*
 * instrument at instruction granularity. If a instruction is detected that it
 * has memory access, insert the detector to check whether the access involves
 * the pointer content of specific syscall in the hotpath.
 *
 * for ppl confused about these memory related IARG-args, post and comments
 * below may help:
 * 
 * https://stackoverflow.com/questions/57030850/
 */
static void insInstrument(INS ins, void *v)
{
    /*
     * note that instruction LEA is ignored by both `INS_IsMemoryRead` and
     * `INS_HasMemoryRead2`, i.e. the bool result would be FALSE, since it
     * doesn't actually reads memory.
     */
    if (INS_IsMemoryRead(ins))
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(memRefDetector),
                       IARG_MEMORYREAD_EA,
                       IARG_END);

    /*
     * at least CMPS and its family instructions use two memory operands, hence
     * we check the second one too.
     */
    if (INS_HasMemoryRead2(ins))
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(memRefDetector),
                       IARG_MEMORYREAD2_EA,
                       IARG_END);
}
/*
static void toolInit(void)
{
    for (int i = 0; i < NR_HOTPATH_CANDIDATE; i++) {
        memset(&hc.candInfo[i], 0, sizeof(struct candidateInfo));
    }
}
*/
static void ThreadStartCb(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    outFile << "app. thread ID "<< threadid << " is now running" << "\n";
}

static void detachCb(void *v)
{
    outFile << "Done";
    outFile.close();
    /* free up memory here */
}

/*
 * only add analysis routine to instructions that lays inside the main
 * executable. Without such filtering, syscall wrappers (e.g. provided by
 * glibc) that access the retval would interfere the accounting of the
 * memory reference count.
 */
static void TraceInstrument(TRACE trace, void *v)
{
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            if (IMG_IsMainExecutable(SEC_Img(RTN_Sec(INS_Rtn(ins))))) {
                if (INS_RegRContain(ins, REG_EAX))
                INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(retvalRefDetector),
                                IARG_BOOL, true,
                                IARG_END);

                if (INS_RegWContain(ins, REG_EAX))
                    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(retvalRefDetector),
                                    IARG_BOOL, false,
                                    IARG_END);
            }
        }
    }
}

int main(int argc, char *argv[])
{
    if (PIN_Init(argc, argv)) {
        outFile << KNOB_BASE::StringKnobSummary() << "\n";
        return EXIT_FAILURE;
    }

    outFile.open(OUTPUT_FILENAME);

    //toolInit();
    if (KnobRetvalChecking)
        TRACE_AddInstrumentFunction(TraceInstrument, 0);
    PIN_AddThreadStartFunction(ThreadStartCb, 0);
    PIN_AddSyscallEntryFunction(syscallEntryCb, NULL);
    INS_AddInstrumentFunction(insInstrument, 0);
    PIN_AddDetachFunction(detachCb, 0);

    if (KnobThreading)
        bt.isThreadingApp = true;

    PIN_StartProgram();

    return EXIT_FAILURE; /* unreachable */
}
