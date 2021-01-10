package com.github.unidbg.arm.backend;

public interface InterruptHook {

    void hook(Backend backend, int intno, int swi, Object user);

}
