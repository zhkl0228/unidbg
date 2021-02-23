package com.github.unidbg.arm.backend;

public interface ReadHook extends Detachable {

    void hook(Backend backend, long address, int size, Object user);

}
