package com.github.unidbg.arm.backend;

import unicorn.Unicorn;

public interface DebugHook extends CodeHook {

    void onBreak(Backend backend, long address, int size, Object user);

    void onAttach(Unicorn.UnHook unHook);

}
