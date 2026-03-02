package com.github.unidbg.arm.backend.hypervisor;

import com.github.unidbg.debugger.BreakPoint;
import com.github.unidbg.debugger.BreakPointCallback;

class HypervisorBreakPoint implements BreakPoint, BreakRestorer {

    private final int slot;
    private final long address;
    private final BreakPointCallback callback;

    public HypervisorBreakPoint(int slot, long address, BreakPointCallback callback) {
        this.slot = slot;
        this.address = address;
        this.callback = callback;
    }

    long getAddress() {
        return address;
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
        hypervisor.install_hw_breakpoint(slot, address);
    }

}
