package com.github.unidbg.arm.backend.hypervisor;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.backend.HypervisorBackend;

public class HypervisorBackend32 extends HypervisorBackend {

    public HypervisorBackend32(Emulator<?> emulator, Hypervisor hypervisor) throws BackendException {
        super(emulator, hypervisor);
    }

}
