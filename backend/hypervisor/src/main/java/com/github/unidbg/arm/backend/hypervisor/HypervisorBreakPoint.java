package com.github.unidbg.arm.backend.hypervisor;

import com.github.unidbg.debugger.BreakPoint;
import com.github.unidbg.debugger.BreakPointCallback;

class HypervisorBreakPoint implements BreakPoint, BreakRestorer {

    private final int n;
    protected final long address;
    private final BreakPointCallback callback;

    public HypervisorBreakPoint(int n, long address, BreakPointCallback callback) {
        this.n = n;
        this.address = address;
        this.callback = callback;
    }

    private boolean temporary;

    @Override
    public boolean isTemporary() {
        return temporary;
    }

    @Override
    public void setTemporary(boolean temporary) {
        this.temporary = temporary;
    }

    @Override
    public BreakPointCallback getCallback() {
        return callback;
    }

    @Override
    public final boolean isThumb() {
        return false;
    }

    @Override
    public void install(Hypervisor hypervisor) {
        hypervisor.install_hw_breakpoint(n, address);
    }

}
