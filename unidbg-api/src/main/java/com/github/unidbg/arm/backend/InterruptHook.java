package com.github.unidbg.arm.backend;

public interface InterruptHook {

    void hook(Backend backend, int intno, Object user);

}
