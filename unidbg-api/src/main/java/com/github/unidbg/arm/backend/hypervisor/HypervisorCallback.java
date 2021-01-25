package com.github.unidbg.arm.backend.hypervisor;

public interface HypervisorCallback {

    int EC_AA64_SVC = 0x15;
    int EC_DATAABORT = 0x24;

    int ARM_EL_ISV_SHIFT = 24;
    int ARM_EL_ISV = (1 << ARM_EL_ISV_SHIFT);

    boolean handleException(long esr, long far, long elr, long spsr);

}
