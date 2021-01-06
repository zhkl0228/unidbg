package com.github.unidbg.arm.backend.hypervisor;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.backend.HypervisorBackend;

public class HypervisorBackend64 extends HypervisorBackend {

    public HypervisorBackend64(Emulator<?> emulator, Hypervisor hypervisor) throws BackendException {
        super(emulator, hypervisor);
    }

    @Override
    public void switchUserMode() {
    }
}
