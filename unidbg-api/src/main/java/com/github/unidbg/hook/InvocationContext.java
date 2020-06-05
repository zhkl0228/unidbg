package com.github.unidbg.hook;

public interface InvocationContext {

    void push(Object... objs);

    <T> T pop();

}
