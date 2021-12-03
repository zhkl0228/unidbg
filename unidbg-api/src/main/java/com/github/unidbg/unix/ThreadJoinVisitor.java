package com.github.unidbg.unix;

import com.sun.jna.Pointer;

public abstract class ThreadJoinVisitor {

    private final boolean saveContext;

    public ThreadJoinVisitor() {
        this(false);
    }

    public ThreadJoinVisitor(boolean saveContext) {
        this.saveContext = saveContext;
    }

    public boolean isSaveContext() {
        return saveContext;
    }

    public abstract boolean canJoin(Pointer start_routine, int threadId);

}
