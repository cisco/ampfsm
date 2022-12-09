### Cisco AMP Filesystem Module (ampfsm.ko)

Russ Kubik

Craig Davison

### Description

This Linux kernel module monitors filesystem syscalls (rename) and sends these
events to user space.

### Supported kernels

This module has been tested on kernels 3.10 (as distributed in CentOS 7) through
4.14 (as distributed in Amazon Linux 2). This module requires jprobes, so kernel
version 4.15 and higher are not currently supported.

### Build the module

Build the module by running make:

```
$ make
```

### Install the kernel module

Install the kernel module:

```
$ sudo insmod ampfsm.ko
```

### Build the test client

Build the test client in the test_client directory
(requires libmnl - http://www.netfilter.org/projects/libmnl/):

```
$ cd test_client
$ make
```

### Run the test client

Run the test client as root:

```
$ sudo ./test_client -l debug -f rename
```

