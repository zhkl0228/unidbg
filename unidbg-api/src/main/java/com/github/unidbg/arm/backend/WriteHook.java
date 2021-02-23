package com.github.unidbg.arm.backend;

public interface WriteHook extends Detachable {

    void hook(Backend backend, long address, int size, long value, Object user);

}
