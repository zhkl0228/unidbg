package com.github.unidbg.unix;

import com.github.unidbg.Emulator;

public abstract class Thread {

    public abstract void runThread(Emulator<?> emulator, long __thread_entry);

}
