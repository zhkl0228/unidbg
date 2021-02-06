package com.github.unidbg.arm.backend.kvm;

public class KvmException extends RuntimeException {

    public KvmException() {
        super();
    }

    public KvmException(String msg) {
        super(msg);
    }

}
