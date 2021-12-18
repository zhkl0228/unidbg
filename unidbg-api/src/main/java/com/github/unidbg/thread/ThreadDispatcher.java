package com.github.unidbg.thread;

import com.github.unidbg.signal.SigSet;
import com.github.unidbg.signal.SignalOps;
import com.github.unidbg.signal.SignalTask;

public interface ThreadDispatcher extends SignalOps {

    void addThread(ThreadTask task);

    Number runMainForResult(MainTask main);

    int getTaskCount();

    boolean sendSignal(int tid, SignalTask signalTask);

}
