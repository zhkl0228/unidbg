package com.github.unidbg.arm.backend.hypervisor;

public interface HypervisorCallback {

    /** SVC instruction execution in AArch64 state */
    int EC_AA64_SVC = 0x15;
    /** Trapped access to system register (MRS/MSR) */
    int EC_SYSTEMREGISTERTRAP = 0x18;
    /** Instruction Abort from a lower Exception level */
    int EC_INSNABORT = 0x20;
    /** Data Abort from a lower Exception level */
    int EC_DATAABORT = 0x24;
    /** Breakpoint exception from a lower Exception level */
    int EC_BREAKPOINT = 0x30;
    /** Software Step exception from a lower Exception level */
    int EC_SOFTWARESTEP = 0x32;
    /** Watchpoint exception from a lower Exception level */
    int EC_WATCHPOINT = 0x34;
    /** BRK instruction execution in AArch64 state */
    int EC_AA64_BKPT = 0x3c;

    /** ISV (Instruction Syndrome Valid) bit position in ESR_ELx */
    int ARM_EL_ISV_SHIFT = 24;
    int ARM_EL_ISV = (1 << ARM_EL_ISV_SHIFT);

    boolean handleException(long esr, long far, long elr, long spsr);
    void handleUnknownException(int ec, long esr, long far, long virtualAddress);

}
