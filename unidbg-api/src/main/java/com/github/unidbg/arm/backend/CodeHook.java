package com.github.unidbg.arm.backend;

public interface CodeHook {

    void hook(Backend backend, long address, int size, Object user);

}
