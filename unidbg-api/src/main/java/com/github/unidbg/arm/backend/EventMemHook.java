package com.github.unidbg.arm.backend;

public interface EventMemHook {

    boolean hook(Backend backend, long address, int size, long value, Object user);

}
