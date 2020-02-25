package com.github.unidbg;

import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnicornPointer;

public interface Svc {

    int CALLBACK_SYSCALL_NUMBER = 0x8888;

    UnicornPointer onRegister(SvcMemory svcMemory, int svcNumber);

    long handle(Emulator<?> emulator);

    void handleCallback(Emulator<?> emulator);

}
