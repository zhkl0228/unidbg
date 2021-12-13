package com.github.unidbg.thread;

public interface ThreadDispatcher {

    void addThread(ThreadTask task);

    Number runMainForResult(MainTask main);

}
