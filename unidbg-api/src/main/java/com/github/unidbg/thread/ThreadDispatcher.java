package com.github.unidbg.thread;

public interface ThreadDispatcher {

    void addTask(Task task);

    Number runMainForResult(MainTask main);

}
