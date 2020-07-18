package com.github.unidbg.debugger;

import com.sun.jna.Pointer;

public interface Breaker {

    void debug();

    void brk(Pointer pc, int svcNumber);

}
