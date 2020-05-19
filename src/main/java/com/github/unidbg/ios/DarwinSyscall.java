package com.github.unidbg.ios;

@SuppressWarnings("unused")
public interface DarwinSyscall {

    int MACH_MSG_SUCCESS = 0x00000000;
    int MACH_MSG_VM_SPACE = 0x00001000; /* No room in VM address space for out-of-line memory. */

    int MACH_SEND_MSG = 0x00000001;
    int MACH_RCV_MSG = 0x00000002;

    int MACH_MSG_PORT_DESCRIPTOR = 0;
    int MACH_MSG_OOL_DESCRIPTOR = 1;
    int MACH_MSGH_BITS_COMPLEX = 0x80000000;	/* message is complex */

    int TASK_BOOTSTRAP_PORT = 4;

    int HOST_PRIORITY_INFO = 5; /* priority information */

    int NOTIFY_STATUS_OK = 0;

    int MAXCOMLEN = 16; /* max command name remembered */

    int SIGBUS	= 10;	/* bus error */

    int CTL_UNSPEC = 0; /* unused */
    int CTL_KERN = 1; /* "high kernel": proc, limits */
    int CTL_NET =	4;		/* network, see socket.h */
    int CTL_HW = 6; /* generic cpu/io */

    int NET_RT_IFLIST =		3;	/* survey interface list */
    int RTM_IFINFO =	0xe;	/* iface going up/down etc. */

    int KERN_OSTYPE	   = 1;	/* string: system version */
    int KERN_OSRELEASE = 2; /* string: system release */
    int KERN_VERSION =	 	 4;	/* string: compile time info */
    int KERN_ARGMAX = 8; /* int: max arguments to exec */
    int KERN_HOSTNAME = 10; /* string: hostname */
    int KERN_PROC = 14; /* struct: process entries */
    int KERN_BOOTTIME =		21;	/* struct: time kernel was booted */
    int KERN_USRSTACK32 = 35; /* int: address of USRSTACK */
    int KERN_PROCARGS2 = 49;
    int KERN_USRSTACK64 = 59;/* LP64 user stack query */
    int KERN_OSVERSION = 65; /* for build number i.e. 9A127 */

    int HW_MACHINE	 = 1;		/* string: machine class */
    int HW_MODEL =	 2;		/* string: specific machine model */
    int HW_NCPU = 3; /* int: number of cpus */
    int HW_PAGESIZE = 7; /* int: software page size */
    int HW_MEMSIZE =	24;		/* uint64_t: physical ram size */
    int HW_CPU_TYPE = 105;
    int HW_CPU_SUBTYPE = 106;
    int HW_CPU_FAMILY = 108;

    int KERN_PROC_PID = 1; /* by process id */

    int CPU_TYPE_ARM = 12;
    int CPU_SUBTYPE_ARM_V7 = 9;

    int CPU_TYPE_ARM64 = 0x100000c;
    int CPU_SUBTYPE_ARM64_ALL = 0;

}
