package com.github.unidbg.arm.backend;

public interface ReadHook {

    void hook(Backend backend, long address, int size, Object user);

}
