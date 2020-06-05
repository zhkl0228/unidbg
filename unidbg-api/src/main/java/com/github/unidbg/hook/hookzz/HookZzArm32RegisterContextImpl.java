package com.github.unidbg.hook.hookzz;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;
import unicorn.ArmConst;

import java.util.Stack;

public class HookZzArm32RegisterContextImpl extends HookZzRegisterContext implements RegisterContext, HookZzArm32RegisterContext {

    private final Pointer reg_ctx;
    private final Emulator<?> emulator;

    HookZzArm32RegisterContextImpl(Emulator<?> emulator, Stack<Object> context) {
        super(context);
        this.reg_ctx = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0).share(8); // skip dummy
        this.emulator = emulator;
    }

    @Override
    public UnicornPointer getPointerArg(int index) {
        if (index < 4) {
            switch (index) {
                case 0:
                    return getR0Pointer();
                case 1:
                    return getR1Pointer();
                case 2:
                    return getR2Pointer();
                case 3:
                    return getR3Pointer();
                default:
                    throw new IllegalArgumentException("index=" + index);
            }
        }

        UnicornPointer sp = getStackPointer();
        return sp.getPointer((index - 4) * emulator.getPointerSize());
    }

    @Override
    public long getR0Long() {
        return reg_ctx.getInt(0) & 0xffffffffL;
    }

    @Override
    public long getR1Long() {
        return reg_ctx.getInt(4) & 0xffffffffL;
    }

    @Override
    public long getR2Long() {
        return reg_ctx.getInt(8) & 0xffffffffL;
    }

    @Override
    public long getR3Long() {
        return reg_ctx.getInt(12) & 0xffffffffL;
    }

    @Override
    public long getR4Long() {
        return reg_ctx.getInt(16) & 0xffffffffL;
    }

    @Override
    public long getR5Long() {
        return reg_ctx.getInt(20) & 0xffffffffL;
    }

    @Override
    public long getR6Long() {
        return reg_ctx.getInt(24) & 0xffffffffL;
    }

    @Override
    public long getR7Long() {
        return reg_ctx.getInt(28) & 0xffffffffL;
    }

    @Override
    public long getR8Long() {
        return reg_ctx.getInt(32) & 0xffffffffL;
    }

    @Override
    public long getR9Long() {
        return reg_ctx.getInt(36) & 0xffffffffL;
    }

    @Override
    public long getR10Long() {
        return reg_ctx.getInt(40) & 0xffffffffL;
    }

    @Override
    public long getR11Long() {
        return reg_ctx.getInt(44) & 0xffffffffL;
    }

    @Override
    public long getR12Long() {
        return reg_ctx.getInt(48) & 0xffffffffL;
    }

    @Override
    public long getLR() {
        return reg_ctx.getInt(52) & 0xffffffffL;
    }

    @Override
    public int getR0Int() {
        return (int) getR0Long();
    }

    @Override
    public int getR1Int() {
        return (int) getR1Long();
    }

    @Override
    public int getR2Int() {
        return (int) getR2Long();
    }

    @Override
    public int getR3Int() {
        return (int) getR3Long();
    }

    @Override
    public int getR4Int() {
        return (int) getR4Long();
    }

    @Override
    public int getR5Int() {
        return (int) getR5Long();
    }

    @Override
    public int getR6Int() {
        return (int) getR6Long();
    }

    @Override
    public int getR7Int() {
        return (int) getR7Long();
    }

    @Override
    public int getR8Int() {
        return (int) getR8Long();
    }

    @Override
    public int getR9Int() {
        return (int) getR9Long();
    }

    @Override
    public int getR10Int() {
        return (int) getR10Long();
    }

    @Override
    public int getR11Int() {
        return (int) getR11Long();
    }

    @Override
    public int getR12Int() {
        return (int) getR12Long();
    }

    @Override
    public UnicornPointer getStackPointer() {
        return (UnicornPointer) reg_ctx.share(56);
    }

    @Override
    public UnicornPointer getR0Pointer() {
        return UnicornPointer.pointer(emulator, getR0Long());
    }

    @Override
    public UnicornPointer getR1Pointer() {
        return UnicornPointer.pointer(emulator, getR1Long());
    }

    @Override
    public UnicornPointer getR2Pointer() {
        return UnicornPointer.pointer(emulator, getR2Long());
    }

    @Override
    public UnicornPointer getR3Pointer() {
        return UnicornPointer.pointer(emulator, getR3Long());
    }

    @Override
    public UnicornPointer getR4Pointer() {
        return UnicornPointer.pointer(emulator, getR4Long());
    }

    @Override
    public UnicornPointer getR5Pointer() {
        return UnicornPointer.pointer(emulator, getR5Long());
    }

    @Override
    public UnicornPointer getR6Pointer() {
        return UnicornPointer.pointer(emulator, getR6Long());
    }

    @Override
    public UnicornPointer getR7Pointer() {
        return UnicornPointer.pointer(emulator, getR7Long());
    }

    @Override
    public UnicornPointer getR8Pointer() {
        return UnicornPointer.pointer(emulator, getR8Long());
    }

    @Override
    public UnicornPointer getR9Pointer() {
        return UnicornPointer.pointer(emulator, getR9Long());
    }

    @Override
    public UnicornPointer getR10Pointer() {
        return UnicornPointer.pointer(emulator, getR10Long());
    }

    @Override
    public UnicornPointer getR11Pointer() {
        return UnicornPointer.pointer(emulator, getR11Long());
    }

    @Override
    public UnicornPointer getR12Pointer() {
        return UnicornPointer.pointer(emulator, getR12Long());
    }

    @Override
    public UnicornPointer getLRPointer() {
        return UnicornPointer.pointer(emulator, getLR());
    }
}
