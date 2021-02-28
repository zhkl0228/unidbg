package com.github.unidbg.arm.backend;

public interface BlockHook extends Detachable {

    void hookBlock(Backend backend, long address, int size, Object user);

}
