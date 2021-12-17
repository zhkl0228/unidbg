package com.github.unidbg.thread;

public interface ThreadDispatcher {

    void addThread(ThreadTask task);

    Number runMainForResult(MainTask main);

    int getTaskCount();

    boolean sendSignal(int tid, SignalTask signalTask);

}
