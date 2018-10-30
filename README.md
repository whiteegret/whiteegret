# WhiteEgret

WhiteEgret is an LSM (Linux Security Modules) to simply provide
a whitelisting-type execution control for the Linux kernel.

## Description

### Background of whitelist

A whitelist is a list of executable components (e.g., applications,
libraries) that are approved to run on a host.
The whitelist is used to decide whether executable components
are permitted to execute or not. This mechanism can stop an
execution of unknown software, so it helps stop executing of
malicious code and other unauthorized software.

It is important to maintain a whitelist properly according to
the execution environments. Managing whitelists for systems
whose execution environments are changed frequently is
a difficult task. On the other hand, for such devices that
continue to do the same tasks for a certain period of time,
we can use the same whitelist for the period once the whitelist
is established. The latter environments are targets of WhiteEgret.
Examples of the environments include control devices in industrial
control systems.

### Goal of WhiteEgret

Although the number of changing whitelists is not so large,
it is necessary to change them according to the system life cycle
or each phase of system operations. There is a requirement
to change whitelists with the system operations continued
because they often cannot easily be stopped.
For example, such cases include temporarily allowing maintenance
programs for maintenance or troubleshooting purposes
while running the systems.

WhiteEgret is aiming at satisfying the above requirement.
WhiteEgret adopts a model that a whitelist is managed in user space.
Namely, WhiteEgret assumes that a privileged user manages
a whitelist in user space. This makes it possible to change
the whitelist while running the systems.

### Mechanism of WhiteEgret

WhiteEgret requires a user application called WhiteEgret User
Application (WEUA, for short). WhiteEgret utilizes the
`bprm_check_security` hook and the `mmap_file` hook.
WhiteEgret asks WEUA whether an executable component
hooked by the above hooks is permitted to execute or not.
If the response from the WEUA is "permit", then WhiteEgret
continues to process the executable component.
If the response is "not permit", then WhiteEgret returns
an error and blocks the execution of the executable component.
The `bprm_check_security` hook is triggered by `execve` system call,
so execution by almost all executable components are hooked
by the hook. However, because shared objects do not invoke `execve`
system call, WhiteEgret utilizes the `mmap_file` hook to hook
the memory mapping by a shared object. Thus WhiteEgret ignores
the `mmap_file` hook caused by non-executable and by executable
which calls `execve` system call.

To ask the permission to a WEUA, WhiteEgret sends the absolute path,
the inode number and the device number of the executable component
to the WEUA. Then the WEUA is expected to work as follows.
The WEUA sees if the tuple of the absolute path and/or the inode
number and/or the device number is contained in the whitelist.
If it exists, the WEUA compares a hash value of the executable
component indicated by the absolute path (and/or the inode number
and/or device number) with that in the whitelist to see
whether the executable component is changed or not after
the whitelist is made. The WEUA returns "permit" if both tests
are passed, otherwise returns "not permit".

WhiteEgret has option to be able to control for script execution.
Some LSM hooks (file_open/file_permission/task_alloc/task_free) are
added. Kernel configs are required to enable the hooks.

Most of interpreters open script files to execute. Therefore
WhiteEgret hooks for reading or opening a file. Then WhiteEgret
asks the WEUA whether an execution of the script is permitted to
execute or not. WhiteEgret is able to choose a hook entry for
execution control between file_open or file_permission.

Hook entries of task_alloc and task_free are used to control
exections of script effectively. Some interpreters forks child
processes to execte script files, so the WEUA managed a process
family of an interpter by bprm_check_security, task_alloc and
task_free.

## Prerequisites

- Ensure that you have source code of the Linux kernel,
version 4.11.0 or later.
- Prepare your own WEUA.
- Prepare your own whitelist.

If you want only to try to run WhiteEgret, use the sample user
application included in this project. In this case, you do not
need to prepare your own WEUA and whitelist.

## Build

1. Download source code of the Linux kernel. (Suppose the source
code is expanded to a directory `KER_DIR`).
2. Clone this project. (Suppose the source code is expanded to a directory `WE_DIR`).
3. Move to directory `KER_DIR`: `$ cd KER_DIR`
4. Copy `WE_DIR/security/whiteegret` to `security/whiteegret`.
5. Edit `security/Kconfig` and `security/Makefile`
according to `WE_DIR/security/Kconfig` and `WE_DIR/security/Makefile`, respectively.
6. Configure with
```
CONFIG_SECURITY_WHITEEGRET=y
```
if option enable to controll script.
```
SECURITY_WHITEEGRET_INTERPRETER=y
```

7. Make and install by running:
```
$ make
$ sudo make modules_install
$ sudo make install
```
8. Boot Linux to the new kernel.

### Build sample user application

If you want to build the sample user application in addition to WhiteEgret,
add the following steps between steps 6 and 7 of the above Build steps.

1. Copy `WE_DIR/samples/whiteegret` to `samples/whiteegret`.
2. Edit `samples/Kconfig` and `samples/Makefile`
according to `WE_DIR/samples/Kconfig` and `WE_DIR/samples/Makefile`,
respectively.
3. Add configuration
```
CONFIG_SAMPLE_WHITEEGRET=y
```

## Usage

WhiteEgret requires a user application WEUA.
In this document, we introduce the sample user application
as a WEUA. This sample user application is built during
the above Build sample user application steps.
The location of the sample user application is
`/lib/modules/$(uname -r)/build/samples/whiteegret/sample-we-user`.

### Sample user application

  sample-we-user `exe` `interpreter exe` `script`

This sample user application always returns "not permit"
for the executable specified by the argument `exe`,
otherwise always returns "permit". Set the absolute path
of an executable to be blocked for `exe`.

If the process of `interpreter exe` opening `script`, WhiteEgret
denies the execution request of the script. If the process opens
the other file, WhiteEgret allows the execution request.

#### Example
```
$ cd /lib/modules/$(uname -r)/build/samples/whiteegret
$ sudo ./sample-we-user /bin/df /bin/perl /tmp/test.pl
```

Then every executions of `/bin/df` are blocked.
The other commands can be issued normally.

If the process family of /bin/perl requests to open
/tmp/test.pl, WhiteEgret denies the request. If the
process family requests to open other file, it is
permitted.

#### Remark

This sample user application does not use a whitelist.
It simply returns "not permit" only when WhiteEgret sends
the absolute path of `argv[1]` to the application.
The reason why this sample user application adopts blacklist-like
approach is to avoid a host to become uncontrollable.
Namely, if this sample provides a sample whitelist and
it misses indispensable executable components for a host,
the host cannot run or stop normally. Because indispensable
executable components depend on each environment,
we decide not to provide a whitelisting-type sample user application.

## Contributing

1. Fork this repository on Github.
2. Clone the project to your own machine.
3. Create your own blanch and change to the blanch.
4. Commit changes to your own blanch.
5. Push your changes.
6. Submit a Pull request so that we can review your changes.

## License

This project is licensed under the GNU General Public License, version 2.
