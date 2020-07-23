package com.github.unidbg.unwind;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.AbstractARM64Emulator;
import com.github.unidbg.pointer.UnicornPointer;
import unicorn.Arm64Const;

public class SimpleARM64Unwinder extends Unwinder {

    @Override
    protected String getBaseFormat() {
        return "[0x%09x]";
    }

    @Override
    public Frame createFrame(UnicornPointer ip, UnicornPointer fp) {
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
        UnicornPointer ip = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR);
        UnicornPointer fp = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_FP);
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

        UnicornPointer ip = frame.fp.getPointer(8);
        UnicornPointer fp = frame.fp.getPointer(0);
        return createFrame(ip, fp);
    }

}
