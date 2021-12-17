package com.github.unidbg.thread;

import com.github.unidbg.AbstractEmulator;

import java.util.List;

public interface Task extends Disposable {

    String TASK_KEY = Task.class.getName();

    int getId();

    boolean canDispatch();

    Number dispatch(AbstractEmulator<?> emulator);

    void saveContext(AbstractEmulator<?> emulator);

    boolean isMainThread();

    boolean isFinish();

    void addSignalTask(SignalTask task);

    List<SignalTask> getSignalTaskList();

    void removeSignalTask(SignalTask task);

    boolean isContextSaved();

    void restoreContext(AbstractEmulator<?> emulator);

}
