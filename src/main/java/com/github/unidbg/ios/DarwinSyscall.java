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

}
