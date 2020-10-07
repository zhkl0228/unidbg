package com.github.unidbg.arm.backend;

public interface BlockHook {

    void hook(Backend backend, long address, int size, Object user);

}
