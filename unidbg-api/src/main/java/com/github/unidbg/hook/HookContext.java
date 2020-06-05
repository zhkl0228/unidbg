package com.github.unidbg.hook;

import com.github.unidbg.arm.context.RegisterContext;

import java.util.Stack;

public abstract class HookContext implements RegisterContext, InvocationContext {

    private final Stack<Object> stack;

    HookContext(Stack<Object> stack) {
        this.stack = stack;
    }

    @Override
    public void push(Object... objs) {
        for (int i = objs.length - 1; i >= 0; i--) {
            stack.push(objs[i]);
        }
    }

    @SuppressWarnings("unchecked")
    @Override
    public <T> T pop() {
        return (T) stack.pop();
    }
}
