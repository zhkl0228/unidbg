package com.github.unidbg.debugger;

import com.github.unidbg.pointer.UnidbgPointer;

public interface Breaker {

    void debug();

    void brk(UnidbgPointer pc, int svcNumber);

}
