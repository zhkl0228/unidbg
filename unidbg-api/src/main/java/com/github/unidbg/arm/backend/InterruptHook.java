package com.github.unidbg.arm.backend;

public interface InterruptHook extends Detachable {

    void hook(Backend backend, int intno, int swi, Object user);

}
