package com.github.unidbg.thread;

import com.github.unidbg.signal.SignalOps;
import com.github.unidbg.signal.SignalTask;

import java.util.List;

public interface ThreadDispatcher extends SignalOps {

    void addThread(ThreadTask task);

    List<Task> getTaskList();

    Number runMainForResult(MainTask main);

    int getTaskCount();

    boolean sendSignal(int tid, SignalTask signalTask);

    RunnableTask getRunningTask();

}
