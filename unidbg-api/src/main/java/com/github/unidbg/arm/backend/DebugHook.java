package com.github.unidbg.arm.backend;

public interface DebugHook extends CodeHook {

    void onBreak(Backend backend, long address, int size, Object user);

}
