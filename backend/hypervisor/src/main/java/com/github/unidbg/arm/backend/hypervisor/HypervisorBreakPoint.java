package com.github.unidbg.arm.backend.hypervisor;

import com.github.unidbg.debugger.BreakPoint;
import com.github.unidbg.debugger.BreakPointCallback;

class HypervisorBreakPoint implements BreakPoint {

    protected final long address;
    private final BreakPointCallback callback;

    public HypervisorBreakPoint(long address, BreakPointCallback callback) {
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

}
