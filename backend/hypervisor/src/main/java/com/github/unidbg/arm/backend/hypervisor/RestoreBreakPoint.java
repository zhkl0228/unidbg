package com.github.unidbg.arm.backend.hypervisor;

abstract class RestoreBreakPoint extends HypervisorBreakPoint {

    protected final int n;

    public RestoreBreakPoint(long address, int n) {
        super(address, null);
        this.n = n;
    }

    public abstract void onRestore();

}
