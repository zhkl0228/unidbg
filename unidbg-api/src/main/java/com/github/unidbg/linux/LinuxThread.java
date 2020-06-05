package com.github.unidbg.linux;

import com.github.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;

public class LinuxThread {

    // Our 'tls' and __pthread_clone's 'child_stack' are one and the same, just growing in
    // opposite directions.
    final Pointer child_stack;
    final UnicornPointer fn;
    final Pointer arg;

    LinuxThread(Pointer child_stack, Pointer fn, Pointer arg) {
        this.child_stack = child_stack;
        this.fn = (UnicornPointer) fn;
        this.arg = arg;
    }

    public long context;

}
