package com.github.unidbg.debugger;

public interface DebugRunnable<T> {

    T runWithArgs(String[] args) throws Exception;

}
