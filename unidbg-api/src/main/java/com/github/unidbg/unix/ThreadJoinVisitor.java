package com.github.unidbg.unix;

import com.sun.jna.Pointer;

public interface ThreadJoinVisitor {

    boolean canJoin(Pointer start_routine, int threadId);

}
