package com.github.unidbg.thread;

import com.github.unidbg.AbstractEmulator;

import java.util.List;

public interface Task extends Disposable {

    String TASK_KEY = Task.class.getName();

    boolean canDispatch();

    Number dispatch(AbstractEmulator<?> emulator);

    void saveContext(AbstractEmulator<?> emulator);

    boolean isMainThread();

    boolean isDead();

    void addSignalTask(SignalTask task);

    List<SignalTask> getSignalTaskList();

    void removeSignalTask(SignalTask task);

}
