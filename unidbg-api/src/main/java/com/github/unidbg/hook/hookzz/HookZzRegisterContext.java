package com.github.unidbg.hook.hookzz;

import com.github.unidbg.arm.context.AbstractRegisterContext;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.hook.InvocationContext;
import com.github.unidbg.pointer.UnidbgPointer;

import java.util.Stack;

public abstract class HookZzRegisterContext extends AbstractRegisterContext implements RegisterContext, InvocationContext {

    private final Stack<Object> stack;

    HookZzRegisterContext(Stack<Object> stack) {
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

    @Override
    public UnidbgPointer getPCPointer() {
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
