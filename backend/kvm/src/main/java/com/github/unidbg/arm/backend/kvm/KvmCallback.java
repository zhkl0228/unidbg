package com.github.unidbg.arm.backend.kvm;

public interface KvmCallback {

    boolean handleException(long esr, long far, long elr, long spsr);

}
