package com.github.unidbg.unwind;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.AbstractARM64Emulator;
import com.github.unidbg.pointer.UnidbgPointer;
import unicorn.Arm64Const;

public class SimpleARM64Unwinder extends Unwinder {

    public SimpleARM64Unwinder(Emulator<?> emulator) {
        super(emulator);
    }

    @Override
    protected String getBaseFormat() {
        return "[0x%09x]";
    }

    @Override
    public Frame createFrame(UnidbgPointer ip, UnidbgPointer fp) {
        if (ip != null) {
            if (ip.peer == AbstractARM64Emulator.LR) {
                return new Frame(ip, null);
            }

            ip = ip.share(-4, 0);
            return new Frame(ip, fp);
        } else {
            return null;
        }
    }

    private Frame initFrame(Emulator<?> emulator) {
        UnidbgPointer ip = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR);
        UnidbgPointer fp = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_FP);
        return createFrame(ip, fp);
    }

    @Override
    protected Frame unw_step(Emulator<?> emulator, Frame frame) {
        if (frame == null) {
            return initFrame(emulator);
        }

        if (frame.fp == null) {
            System.err.println("fp is null");
            return null;
        }

        UnidbgPointer ip = frame.fp.getPointer(8);
        UnidbgPointer fp = frame.fp.getPointer(0);
        return createFrame(ip, fp);
    }

}
