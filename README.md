# Hotpath Finder
A tool for finding [hotpath](https://en.wikipedia.org/wiki/Hot_spot_(computer_programming)) in an application (typically long running process, e.g. web server, database, etc.). The tool is used mainly for assisting live binary patching, the goal of the patching is to make the binary more friendly for doing syscall batching. Related syscall batching project is [dBatch](https://github.com/eecheng87/dBatch).

The output of the tool is a pruned hotpath, the hotpath would contains only syscalls that are interested by the user, and these syscalls have no pointer parameter dependency (if the syscall has such param) in the hotpath of the application, i.e. application logic doesn't uses content pointed to by these pointers.

## Usage
Since the tool is built upon [Intel Pin](https://software.intel.com/content/www/us/en/develop/articles/pin-a-dynamic-binary-instrumentation-tool.html), one would need to download it [here](https://software.intel.com/content/www/us/en/develop/articles/pin-a-binary-instrumentation-tool-downloads.html), untar it to the root directory of the project. (The ELF of [Intel Pin](https://software.intel.com/content/www/us/en/develop/articles/pin-a-dynamic-binary-instrumentation-tool.html) can be located under the untar-ed directory)

Then run:
```
make PIN_ROOT=<directory name of the untar-ed archive>
```
to build the tool.

After building the tool, there should be a directory named `obj-intel64` in the project directory, the tool (`.o` and `.so`) should be located inside it.

[Intel Pin](https://software.intel.com/content/www/us/en/develop/articles/pin-a-dynamic-binary-instrumentation-tool.html) can  start/attach to the application by issuing:
```
<path to the Pin ELF> -t obj-intel64/hotpathFinder.so -- <application command and options>
```
and
```
<path to the Pin ELF> -pid <pid of the app. to be attach to> -t obj-intel64/hotpathFinder.so
```
respectively.

For the latter command, one may be restricted by the OS. For enabling Pin to perform the injection, use:
```
sudo sh -c 'echo 0 > /proc/sys/kernel/yama/ptrace_scope'
```
(Be aware that this would enable unprivileged process to do malicious injection to other processes.)

### Options
- `mt`

    For threading application, one would need to enable `-mt` flag to make the tool works properly:
    ```
    <path to the Pin ELF> -pid <pid of the app. to attach> -t obj-intel64/hotpathFinder.so -mt
    ```
    or
    ```
    <path to the Pin ELF> -t obj-intel64/hotpathFinder.so -mt -- <application to start>
    ```

- `retval`

    Syscall-retval-reference checking can be enabled by specifying `-retval` flag.

Once the tool is attached to the application, one would need to put some loading to the application if it's idling at the time, i.e. the tool can't make progress if the application is idling. It's noteworthy that due to our profiling mechanism, only run through the hotpath once (e.g. single HTTP request) is not enough to finish the profiling, and twice is enough currently.

After profiling, the resulting file (profiling result) can be found at directory where the application is started. Meanwhile, the tool would detach from the application, which means that the application would execute on its own behalf since then.

Unfortunately, the tool can't get correct hotpath by starting the application with Pin for now, it's because of bad hotpath finding mechanism. The mechanism we use currently is recording the backtrace of each syscall, after each recording, we check whether we have duplicated backtrace existed, if it does, we consider the hotpath is found. However, at least CRT (C runtime) has such scenario at application loading stage, which makes the tool to get wrong hotpath. Therefore, we can only use attach mode profile the target application currently.

## Adding new syscall
As each syscall has different sequence of pointer param (if any), the tool currently uses a cumbersome (hard-coded) mechanism for supported syscall. In order to add new syscall, one would require:
1. add target syscall number into array named `whitelistedSyscall`.
2. add new `case` into `chkMemRefBySyscall`, the constant integer stands for the seq. of the param of the syscall starting from zero.
3. add new `case` into `addMemRefTarget`, to be specific:
    - specify how many ptr params the syscall has.
    - specify the seq. of the param (starting from zero).
    - place macro `INC_CUR_IDX` at the end of the case (regardless of whether the syscall has ptr param).
    - `break` the case.

## TODOs
- Better hotpath finding mechanism is required as current one may captures unwanted code path.
## Example output
With Nginx as profiling target:

- application logic inside Nginx also suffered from the aforementioned deficiency, which causes missing of 3 syscalls in the hotpath.
- `cLoc` stands for syscall location in our buffer, it's also the syscall sequence in the hotpath.
- `cSpan` stands for how many syscalls specific candidate covers.

```
app. thread ID 0 is now running

There are totally 11 syscalls found within the hotpath.
First stage prune (filter out syscalls that don't exist in the whitelist):
cand. #0 has cLoc: 0, cSpan: 7
cand. #1 has cLoc: 8, cSpan: 3

Second stage prune (filter out syscalls that have refcnt of ptr param and syscall retval > 0):
cLoc:5 has memref count of 1
cLoc:2 has memref count of 2
new candidate (#2) has cLoc: 3, cSpan: 2
cLoc:1 has memref count of 6

After pruning, we got 3 candidate(s) for doing syscall batching:

candidate #0 has too few syscalls for batching.

candidate #1 contains 3 syscalls

syscall #0 has backtrace:
0x00007fcf9c9433d5 --> .text+0x00000c8f5 at /lib/x86_64-linux-gnu/libpthread+0x0000143d5
0x00005576d411e0ce --> .text+0x000002eee at /home/dces4212/project/nginx-1.18.0/objs/nginx+0x00001c0ce (/home/dces4212/project/orig_nginx-1.18/nginx-1.18.0/src/core/ngx_palloc.c:371)
0x00005576d411e295 --> .text+0x0000030b5 at /home/dces4212/project/nginx-1.18.0/objs/nginx+0x00001c295 (/home/dces4212/project/orig_nginx-1.18/nginx-1.18.0/src/core/ngx_palloc.c:57)
0x00005576d41514b6 --> .text+0x000005596 at /home/dces4212/project/nginx-1.18.0/objs/nginx+0x00004f4b6 (/home/dces4212/project/orig_nginx-1.18/nginx-1.18.0/src/http/ngx_http_request.c:3650)

...
```

## Notes
Currently tested runnable version of [Intel Pin](https://software.intel.com/content/www/us/en/develop/articles/pin-a-dynamic-binary-instrumentation-tool.html) is `pin-3.17-98314`.