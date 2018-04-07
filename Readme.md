## Overview
This project uses LSM hooks to enforce a simple access control policy. The implementation associates the 
path of a binary file which is allowed to access a protected file. The path of the binary file is stored in the extended attribute
(XAttr) of the inode of the protected file. When a process tries to access this file, the path of the binary which was
loaded during the exec() call of the process is checked against the XAttr attribute ("security.pindown" in this case). If the
path matches then the process is allowed to access the file. Otherwise, access is denied.  

#### PinDOWN LSM implementation
Pindown module that implements the four hooks listed below which are exposed by the Linux Security Modules framework:
* task_alloc_security <br>
* task_free_security <br>
* bprm_set_security <br>
* inode_permission <br>

This implementation is tested for the linux kernel version 2.6.23. The diagram below shows how the implementation control 
access to files using LSM hooks.
![Access Control using Pindown LSM](https://github.com/atambol/Linux-Security-Module/blob/master/flow.png "Flow of control")

#### Commands to load the module
* Download the kernel linux-2.6.23. Older distros of linux such as ubuntu 8.04 LTS can be used because it allows loading kernel modules without reboot. <br>
* Copy `pindown.c` and `Makefile` to linux-2.6.23/security directory. <br>
* Run `make all` in the root directory of the kernel repository. This generates the kernel object `security/pindown.ko`. <br>
* To insert the module, run `insmod security/pindown.ko`. The hooks provided in the module should enforce access control.  <br>
* Logs can be accessed in the file `/var/log/kern.log`. Check if the modules is loaded using `lsmod` command. <br>

#### Setting the access control for policy
Following example limits the acces to file `/foo/bar/protected_file` to the program `/usr/bin/vi` only.
Any other program, trying to access the file would be denied access to the protected file. <br>
* Set the XAttr attribute on the protected file. <br>
`sudo setfattr -n security.pindown -v '/usr/bin/vi' /foo/bar/protected_file` <br>
* Check the XAttr attribute <br>
`sudo getfattr -n security.pindown /foo/bar/protected_file` <br>
* Load the `pindown.ko` module as shown in the previous section. <br>

With that, only `vi` program should be have access to the file. Any other program attempting to access the file would be denied the permission.  

#### References
The project is inspired from the [PinUP](https://enck.org/pubs/acsac08a.pdf) paper. <br>
[Linux Security Module Framework](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.124.5163&rep=rep1&type=pdf)