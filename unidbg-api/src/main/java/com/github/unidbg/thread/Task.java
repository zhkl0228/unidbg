package com.github.unidbg.thread;

import com.github.unidbg.AbstractEmulator;

public interface Task {

    String TASK_KEY = Task.class.getName();

    boolean canDispatch();

    Number dispatch(AbstractEmulator<?> emulator);

    void saveContext(AbstractEmulator<?> emulator);

    boolean isMainThread();

    void destroy(AbstractEmulator<?> emulator);

}
