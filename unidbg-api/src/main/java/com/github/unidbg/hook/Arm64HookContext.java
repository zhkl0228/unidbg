package com.github.unidbg.hook;

import com.github.unidbg.arm.context.EditableArm64RegisterContext;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;

import java.util.Stack;

class Arm64HookContext extends HookContext implements EditableArm64RegisterContext {

    private final EditableArm64RegisterContext registerContext;

    Arm64HookContext(Stack<Object> stack, EditableArm64RegisterContext registerContext) {
        super(stack);
        this.registerContext = registerContext;
    }

    @Override
    public void setXLong(int index, long value) {
        registerContext.setXLong(index, value);
    }

    @Override
    public void setStackPointer(Pointer sp) {
        registerContext.setStackPointer(sp);
    }

    @Override
    public long getXLong(int index) {
        return registerContext.getXLong(index);
    }

    @Override
    public int getXInt(int index) {
        return registerContext.getXInt(index);
    }

    @Override
    public UnidbgPointer getXPointer(int index) {
        return registerContext.getXPointer(index);
    }

    @Override
    public long getFp() {
        return registerContext.getFp();
    }

    @Override
    public UnidbgPointer getFpPointer() {
        return registerContext.getFpPointer();
    }

    @Override
    public int getIntArg(int index) {
        return registerContext.getIntArg(index);
    }

    @Override
    public long getLongArg(int index) {
        return registerContext.getLongArg(index);
    }

    @Override
    public UnidbgPointer getPointerArg(int index) {
        return registerContext.getPointerArg(index);
    }

    @Override
    public long getLR() {
        return registerContext.getLR();
    }

    @Override
    public UnidbgPointer getLRPointer() {
        return registerContext.getLRPointer();
    }

    @Override
    public UnidbgPointer getPCPointer() {
        return registerContext.getPCPointer();
    }

    @Override
    public UnidbgPointer getStackPointer() {
        return registerContext.getStackPointer();
    }

    @Override
    public int getInt(int regId) {
        return registerContext.getInt(regId);
    }

    @Override
    public long getLong(int regId) {
        return registerContext.getLong(regId);
    }
}
