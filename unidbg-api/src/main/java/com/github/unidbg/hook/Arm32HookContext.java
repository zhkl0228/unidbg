package com.github.unidbg.hook;

import com.github.unidbg.arm.context.EditableArm32RegisterContext;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;

import java.util.Stack;

class Arm32HookContext extends HookContext implements EditableArm32RegisterContext {

    private final EditableArm32RegisterContext registerContext;

    Arm32HookContext(Stack<Object> stack, EditableArm32RegisterContext registerContext) {
        super(stack);
        this.registerContext = registerContext;
    }

    @Override
    public void setR0(int r0) {
        registerContext.setR0(r0);
    }

    @Override
    public void setR1(int r1) {
        registerContext.setR1(r1);
    }

    @Override
    public void setR2(int r2) {
        registerContext.setR2(r2);
    }

    @Override
    public void setR3(int r3) {
        registerContext.setR3(r3);
    }

    @Override
    public void setR4(int r4) {
        registerContext.setR4(r4);
    }

    @Override
    public void setR5(int r5) {
        registerContext.setR5(r5);
    }

    @Override
    public void setR6(int r6) {
        registerContext.setR6(r6);
    }

    @Override
    public void setR7(int r7) {
        registerContext.setR7(r7);
    }

    @Override
    public void setStackPointer(Pointer sp) {
        registerContext.setStackPointer(sp);
    }

    @Override
    public long getR0Long() {
        return registerContext.getR0Long();
    }

    @Override
    public long getR1Long() {
        return registerContext.getR1Long();
    }

    @Override
    public long getR2Long() {
        return registerContext.getR2Long();
    }

    @Override
    public long getR3Long() {
        return registerContext.getR3Long();
    }

    @Override
    public long getR4Long() {
        return registerContext.getR4Long();
    }

    @Override
    public long getR5Long() {
        return registerContext.getR5Long();
    }

    @Override
    public long getR6Long() {
        return registerContext.getR6Long();
    }

    @Override
    public long getR7Long() {
        return registerContext.getR7Long();
    }

    @Override
    public long getR8Long() {
        return registerContext.getR8Long();
    }

    @Override
    public long getR9Long() {
        return registerContext.getR9Long();
    }

    @Override
    public long getR10Long() {
        return registerContext.getR10Long();
    }

    @Override
    public long getR11Long() {
        return registerContext.getR11Long();
    }

    @Override
    public long getR12Long() {
        return registerContext.getR12Long();
    }

    @Override
    public int getR0Int() {
        return registerContext.getR0Int();
    }

    @Override
    public int getR1Int() {
        return registerContext.getR1Int();
    }

    @Override
    public int getR2Int() {
        return registerContext.getR2Int();
    }

    @Override
    public int getR3Int() {
        return registerContext.getR3Int();
    }

    @Override
    public int getR4Int() {
        return registerContext.getR4Int();
    }

    @Override
    public int getR5Int() {
        return registerContext.getR5Int();
    }

    @Override
    public int getR6Int() {
        return registerContext.getR6Int();
    }

    @Override
    public int getR7Int() {
        return registerContext.getR7Int();
    }

    @Override
    public int getR8Int() {
        return registerContext.getR8Int();
    }

    @Override
    public int getR9Int() {
        return registerContext.getR9Int();
    }

    @Override
    public int getR10Int() {
        return registerContext.getR10Int();
    }

    @Override
    public int getR11Int() {
        return registerContext.getR11Int();
    }

    @Override
    public int getR12Int() {
        return registerContext.getR12Int();
    }

    @Override
    public UnidbgPointer getR0Pointer() {
        return registerContext.getR0Pointer();
    }

    @Override
    public UnidbgPointer getR1Pointer() {
        return registerContext.getR1Pointer();
    }

    @Override
    public UnidbgPointer getR2Pointer() {
        return registerContext.getR2Pointer();
    }

    @Override
    public UnidbgPointer getR3Pointer() {
        return registerContext.getR3Pointer();
    }

    @Override
    public UnidbgPointer getR4Pointer() {
        return registerContext.getR4Pointer();
    }

    @Override
    public UnidbgPointer getR5Pointer() {
        return registerContext.getR5Pointer();
    }

    @Override
    public UnidbgPointer getR6Pointer() {
        return registerContext.getR6Pointer();
    }

    @Override
    public UnidbgPointer getR7Pointer() {
        return registerContext.getR7Pointer();
    }

    @Override
    public UnidbgPointer getR8Pointer() {
        return registerContext.getR8Pointer();
    }

    @Override
    public UnidbgPointer getR9Pointer() {
        return registerContext.getR9Pointer();
    }

    @Override
    public UnidbgPointer getR10Pointer() {
        return registerContext.getR10Pointer();
    }

    @Override
    public UnidbgPointer getR11Pointer() {
        return registerContext.getR11Pointer();
    }

    @Override
    public UnidbgPointer getR12Pointer() {
        return registerContext.getR12Pointer();
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
