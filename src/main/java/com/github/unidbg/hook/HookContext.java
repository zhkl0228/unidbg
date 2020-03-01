package com.github.unidbg.hook;

import com.github.unidbg.arm.context.RegisterContext;

import java.util.Stack;

public abstract class HookContext implements RegisterContext, InvocationContext {

    private final Stack<Object> stack;

    HookContext(Stack<Object> stack) {
        this.stack = stack;
    }

    @Override
    public void push(Object obj) {
        stack.push(obj);
    }

    @SuppressWarnings("unchecked")
    @Override
    public <T> T pop() {
        return (T) stack.pop();
    }
}
