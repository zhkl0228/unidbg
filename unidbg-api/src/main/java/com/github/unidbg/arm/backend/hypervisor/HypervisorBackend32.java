package com.github.unidbg.arm.backend.hypervisor;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.backend.HypervisorBackend;

public class HypervisorBackend32 extends HypervisorBackend {

    public HypervisorBackend32(Emulator<?> emulator, Hypervisor hypervisor) throws BackendException {
        super(emulator, hypervisor);
    }

    @Override
    public boolean handleException(long esr, long far, long elr) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void enableVFP() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void switchUserMode() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void reg_write(int regId, Number value) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public Number reg_read(int regId) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    protected byte[] addSoftBreakPoint(long address, int svcNumber, boolean thumb) {
        throw new UnsupportedOperationException();
    }
}
