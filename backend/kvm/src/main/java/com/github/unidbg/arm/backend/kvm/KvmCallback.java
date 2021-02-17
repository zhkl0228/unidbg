package com.github.unidbg.arm.backend.kvm;

public interface KvmCallback {

    int EC_AA64_SVC = 0x15;
    int EC_INSNABORT = 0x20;
    int EC_DATAABORT = 0x24;
    int EC_AA64_BKPT = 0x3c;

    boolean handleException(long esr, long far, long elr, long spsr, long pc);

}
