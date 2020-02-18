package com.github.unidbg;

import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnicornPointer;

public interface Svc {

    UnicornPointer onRegister(SvcMemory svcMemory, int svcNumber);

    long handle(Emulator emulator);

    long handleCallback(Emulator emulator);

}
