package com.github.unidbg.hook.hookzz;

import com.github.unidbg.arm.context.AbstractRegisterContext;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.hook.InvocationContext;
import com.github.unidbg.pointer.UnicornPointer;

import java.util.Stack;

public abstract class HookZzRegisterContext extends AbstractRegisterContext implements RegisterContext, InvocationContext {

    private final Stack<Object> stack;

    HookZzRegisterContext(Stack<Object> stack) {
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

    @Override
    public UnicornPointer getPCPointer() {
        throw new UnsupportedOperationException();
    }

    @Override
    public int getInt(int regId) {
        throw new UnsupportedOperationException();
    }

    @Override
    public long getLong(int regId) {
        throw new UnsupportedOperationException();
    }
}
