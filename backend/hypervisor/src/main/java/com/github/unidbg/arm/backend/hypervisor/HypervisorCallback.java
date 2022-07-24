package com.github.unidbg.arm.backend.hypervisor;

public interface HypervisorCallback {

    int EC_AA64_SVC = 0x15;
    int EC_BREAKPOINT = 0x30;
    int EC_SOFTWARESTEP = 0x32;
    int EC_WATCHPOINT = 0x34;
    int EC_AA64_BKPT = 0x3c;
    int EC_INSNABORT = 0x20;
    int EC_DATAABORT = 0x24;

    int ARM_EL_ISV_SHIFT = 24;
    int ARM_EL_ISV = (1 << ARM_EL_ISV_SHIFT);

    boolean handleException(long esr, long far, long elr, long spsr);
    void handleUnknownException(int ec, long esr, long far, long virtualAddress);

}
