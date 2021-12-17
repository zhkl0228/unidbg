package com.github.unidbg.thread;

import com.github.unidbg.signal.SigSet;
import com.github.unidbg.signal.SignalTask;

public interface ThreadDispatcher {

    void addThread(ThreadTask task);

    Number runMainForResult(MainTask main);

    int getTaskCount();

    boolean sendSignal(int tid, SignalTask signalTask);

    SigSet getMainThreadSigMaskSet();
    void setMainThreadSigMaskSet(SigSet mainThreadSigMaskSet);
    SigSet getMainThreadSigPendingSet();
    void setMainThreadSigPendingSet(SigSet mainThreadSigPendingSet);

}
