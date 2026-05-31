---
title: "Understanding EDR Telemetry: Linux Script Activity"
date: 2026-05-30T15:16:00+02:00
author: j91321
categories:
- EDR Telemetry
tags:
- EDR
- detection engineering
- Linux
#images: ["images/ebpf.png"] # OpenGraph setting
#bookPostThumbnail: "images/ebpf.png"
# bookComments: false
# bookSearchExclude: false
# bookPostThumbnail: thumbnail.*
---
Having visibility into PowerShell on Windows is pretty standard feature for every modern EDR, as PowerShell has been used and abused by adversaries for over 20 years at this point. Yet, on Linux where having introspection into scripts seem even more important tracking script activity is far from a standard feature. On Windows we can thank the Antimalware Scan Interface (AMSI) for visibility into PowerShell. On Linux we don't have the luxury of AMSI.

Let's take a look at how some visibility into scripts can be achieved on modern Linux.

## Understanding shebang execution

Some Linux EDR agents provide script execution events. They can vary in verbosity, sometimes with the caveat that the event is only generated for scripts that start with [shebang](https://en.wikipedia.org/wiki/Shebang_(Unix)) `#!`. Shebang is used to point to the correct interpreter of a script file. Consider the following script:

```python
#!/usr/bin/python3

import os
print("This process has the PID", os.getpid())
```

being executed like this:
``` bash
$ chmod +x ./pid.py
$ ./pid.py
This process has the PID 12569
```

The question here is, who is responsible for launching the correct interpreter? Is it shell e.g. `bash` or could it be kernel? Turns out it's the kernel, as explained in THC article [How does Linux start a process](https://iq.thc.org/how-does-linux-start-a-process):

> *From there into search_binary_handler() where the Kernel checks if the binary is ELF, a shebang (#!) or any other type registered via the binfmt-misc module. The kernel then calls the appropriate function to load the binary.*

The responsible kernel function is [`load_script`](https://github.com/torvalds/linux/blob/master/fs/binfmt_script.c#L34). Modern Linux EDR agents rely on extended Berkeley Packet Filter (eBPF) for monitoring kernel. In the old days security solutions had to rely on building, often unstable, kernel modules. So let's try to replicate how such event could be implemented with eBPF using [`bpftrace`](https://bpftrace.org/) (because I'm lazy to write C). I'll be using Ubuntu 26.04 LTS with `7.0.0-22-generic` kernel.

## Monitoring shebang script execution using bpftrace

Let's add kernel probe using `bpftrace` to `load_script` kernel function:

```bash
sudo bpftrace -e 'kprobe:load_script { printf("load_script called by %s (%s)\n", comm, pid); }'
```

Now run `pid.py`:

```bash
./pid.py
This process has the PID 14340
```

The output of `bpftrace` should look something like this:
```
Attached 1 probe
load_script called by bash (14331)
load_script called by bash (14339)
load_script called by bash (14340)
load_script called by bash (14340)
load_script called by bash (14344)
```

We see a bunch of `bash` processes, among them our PID **14340**. The `comm` variable contains the current task name in the kernel, which hasn't yet been updated to `python3`, because `execve` hasn't finish at that point.

We need more information to understand what exactly is happening here, since there are more `load_script` calls than expected. Let's modify our probe to display other information that's accessible within the function. By accessing struct [`linux_binprm`](https://github.com/torvalds/linux/blob/master/include/linux/binfmts.h#L18C8-L18C20) defined in `include/linux/binfmts.h` we can display more information about the process. 

Notice the comment next to `const char *interp;`:

> *Name of the binary really executed. Most of the time same as filename, but could be different for binfmt_{misc,script}*

Run the modified `bpftrace`:

```bash
sudo bpftrace -e '
kprobe:load_script
{
    $bprm = (struct linux_binprm *)arg0;
    printf("load_script called by %s (%d) filename=%s bprm_interp=%s\n", comm, pid,
    str($bprm->filename), str($bprm->interp));
}'
```

With information from `linux_binprm` we can actually see the parsed shebang value:

```
load_script called by bash (24365) filename=/usr/bin/sed bprm_interp=/usr/bin/sed
load_script called by bash (24366) filename=./pid.py bprm_interp=./pid.py
load_script called by bash (24366) filename=./pid.py bprm_interp=/usr/bin/python3
load_script called by bash (24370) filename=/usr/bin/sed bprm_interp=/usr/bin/sed
```

The `sed` execution is related to internal workings of `bash`. If you use `sh` instead, it'll report only the two lines related to `pid.py`. There is still something interesting happening here, there are two entries for **24366** and one of the entries has `bprm_interp` set to the same value as filename. 

This happens in function [`bprm_change_interp`](https://github.com/torvalds/linux/blob/master/fs/exec.c#L1469) that's called in `load_script` to swap the interpreter. We can attach our probe to it with the following command:

```bash
sudo bpftrace -e '
kprobe:bprm_change_interp
{
    $i_name = arg0;
    $bprm = (struct linux_binprm *)arg1;
    printf("bprm_change_interp called by %s (%d) interpreter=%s filename=%s bprm_interp=%s\n", comm, pid,
    str($i_name), str($bprm->filename), str($bprm->interp));
}'
```

```
bprm_change_interp called by bash (25688) interpreter=/usr/bin/python3 filename=./pid.py bprm_interp=./pid.py
```

Next the process execution is restarted and runs `python3`. That should be the second `load_script` entry. This is pretty close to how monitoring script events could be implemented. To get the content of the script agent can just read the file. Similar probe can be found in [redcanary-ebpf-sensor](https://github.com/redcanaryco/redcanary-ebpf-sensor/blob/main/src/process-events.c#L212). Of course it relies on the shebang being used for execution, launching the process directly using interpreter e.g. `python3 ./pid.py` won't trigger any events. This event nicely complements standard syscall monitoring of `execve`.

As a side note, the Endpoint Security framework on macOS provides similar functionality. Script property in [`es_event_exec_t`](https://developer.apple.com/documentation/endpointsecurity/es_event_exec_t) reports script interpreters that were launched using shebang on macOS. For more macOS and Endpoint Security framework details I recommend [Threat Hunting macOS: Mastering Endpoint Security](https://themittenmac.com/threat-hunting-book/) by Jaron Bradley.

## Tracking Shell Commands

Another interesting problem EDRs face is having introspection into interactive shell activity. Defenders want to track commands issued by the adversary as they are passed to the shell e.g. `bash`. Reconstructing complex shell constructs with pipes and input redirects, using only process information, may not be a trivial task. To obtain direct visibility into `bash` we'll use dynamic user probes (`uprobes`). These allow you to hook functions in userland binaries through kernel. A more detailed explanation can be found in bpftrace hands on lab [Working with dynamic user probes](https://bpftrace.org/hol/user-probes). 

Interesting place for our probe is return from function `readline` in `bash`. You can discover available functions in `/usr/bin/bash` using `nm` for example:

```
$ nm -D /usr/bin/bash | grep -iE "readline"
0000000000178a78 B bash_readline_initialized
00000000001787d8 B current_readline_line
00000000001787d0 B current_readline_line_index
0000000000177f40 B current_readline_prompt
00000000000afe20 T initialize_readline
00000000000bb6e0 T pcomp_set_readline_variables
00000000000b1780 T posix_readline_initialize
0000000000105e20 T readline
00000000000fdb60 T readline_common_teardown
00000000000ff6f0 T readline_internal_char
00000000000fd930 T readline_internal_setup
00000000000fdd60 T readline_internal_teardown
000000000017786c D rl_gnu_readline_p
0000000000176790 D rl_readline_name
0000000000178a70 B rl_readline_state
0000000000177868 D rl_readline_version
```

This only works because, `bash` exports `readline` as dynamic symbol. If the binary was stripped down, this approach wouldn't work. Now, place `uretprobe`:

```bash
sudo bpftrace -e '
uretprobe:/usr/bin/bash:readline
{
    printf("%s (%d) user entered: %s\n", comm, pid, str(retval));
}'
```

Execute some commands:

```bash
$ echo "Hello World"
Hello World
$ cat pid.py
#! /usr/bin/python3

import os
print("This process has the PID", os.getpid())
$ echo "Write to file" >> "test.txt"
$ ls -ltr
total 12
-rwxrwxr-x 1 john john 79 May 30 12:14 pid.py
-rwxrwxr-x 1 john john 20 May 31 09:08 pid.sh
-rw-rw-r-- 1 john john 14 May 31 13:00 test.txt
$ history | grep ssh
```

Your probe should output everything that was written in the command prompt:

```
bash (3851) user entered: echo "Hello World"
bash (3851) user entered: cat pid.py
bash (3851) user entered: echo "Write to file" >> "test.txt"
bash (3851) user entered: ls -ltr
bash (3851) user entered: history | grep ssh
```

A similar probe implementation can be found in [Cybereason owLSM](https://github.com/Cybereason-Public/owLSM/blob/main/src/Kernel/Programs/shell_command_monitoring/bash_shell_command.bpf.c#L20).


