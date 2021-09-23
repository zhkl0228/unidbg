package com.github.unidbg.linux.thread;

import com.sun.jna.Pointer;

public interface ThreadJoinVisitor {

    boolean canJoin(Pointer start_routine, int threadId);

}
