package cn.banny.unidbg.ios;

public interface DarwinSyscall {

    int MACH_MSG_SUCCESS = 0x00000000;

    int MACH_SEND_MSG = 0x00000001;
    int MACH_RCV_MSG = 0x00000002;

    int MACH_MSG_PORT_DESCRIPTOR = 0;
    int MACH_MSGH_BITS_COMPLEX = 0x80000000;	/* message is complex */

    int TASK_BOOTSTRAP_PORT = 4;

    int HOST_PRIORITY_INFO = 5; /* priority information */

}
