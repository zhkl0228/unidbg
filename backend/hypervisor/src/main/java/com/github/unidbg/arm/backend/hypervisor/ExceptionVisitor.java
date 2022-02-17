package com.github.unidbg.arm.backend.hypervisor;

abstract class ExceptionVisitor {

    protected final int n;

    public ExceptionVisitor(int n) {
        super();
        this.n = n;
    }

    public abstract void onException();

}
