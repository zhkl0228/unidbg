package com.github.unidbg.unix;

import com.github.unidbg.Emulator;
import com.github.unidbg.thread.ThreadTask;

public abstract class Thread extends ThreadTask {

    public Thread(int tid, long until) {
        super(tid, until);
    }

    public abstract void runThread(Emulator<?> emulator, long __thread_entry, long timeout);

}
