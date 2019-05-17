package cn.banny.unidbg.linux;

import com.sun.jna.Pointer;

public class LinuxThread {

    // Our 'tls' and __pthread_clone's 'child_stack' are one and the same, just growing in
    // opposite directions.
    final Pointer child_stack;
    final Pointer fn;
    final Pointer arg;

    LinuxThread(Pointer child_stack, Pointer fn, Pointer arg) {
        this.child_stack = child_stack;
        this.fn = fn;
        this.arg = arg;
    }

    public long context;

}
