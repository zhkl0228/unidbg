package com.github.unidbg.thread;

import com.github.unidbg.AbstractEmulator;

import java.util.List;

public interface Task {

    String TASK_KEY = Task.class.getName();

    boolean canDispatch();

    Number dispatch(AbstractEmulator<?> emulator);

    void saveContext(AbstractEmulator<?> emulator);

    boolean isMainThread();

    void destroy(AbstractEmulator<?> emulator);

    boolean isDead();

    void addSignalTask(Task task);

    List<Task> getSignalTaskList();

    void removeSignalTask(Task task);

}
