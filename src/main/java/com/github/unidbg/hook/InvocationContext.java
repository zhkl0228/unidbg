package com.github.unidbg.hook;

public interface InvocationContext {

    void push(Object obj);

    <T> T pop();

}
