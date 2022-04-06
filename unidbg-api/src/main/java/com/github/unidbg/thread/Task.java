package com.github.unidbg.thread;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.signal.SignalOps;
import com.github.unidbg.signal.SignalTask;

import java.util.List;

public interface Task extends SignalOps, RunnableTask {

    String TASK_KEY = Task.class.getName();

    int getId();

    Number dispatch(AbstractEmulator<?> emulator) throws PopContextException;

    boolean isMainThread();

    boolean isFinish();

    void addSignalTask(SignalTask task);

    List<SignalTask> getSignalTaskList();

    void removeSignalTask(SignalTask task);

    boolean setErrno(Emulator<?> emulator, int errno);

}
