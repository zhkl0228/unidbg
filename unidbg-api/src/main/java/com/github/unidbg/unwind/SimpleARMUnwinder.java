package com.github.unidbg.unwind;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.AbstractARMEmulator;
import com.github.unidbg.pointer.UnicornPointer;
import unicorn.ArmConst;

public class SimpleARMUnwinder extends Unwinder {

    @Override
    protected String getBaseFormat() {
        return "[0x%08x]";
    }

    @Override
    public Frame createFrame(UnicornPointer ip, UnicornPointer fp) {
        if (ip != null) {
            if (ip.peer == AbstractARMEmulator.LR) {
                return new Frame(ip, null);
            }

            boolean thumb = (ip.peer & 1) == 1;
            ip = ip.share(thumb ? -2 : -4, 0);
            return new Frame(ip, fp);
        } else {
            return null;
        }
    }

    private Frame initFrame(Emulator<?> emulator) {
        UnicornPointer ip = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR);
        UnicornPointer fp = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R7);
        return createFrame(ip, fp);
    }

    @Override
    protected Frame unw_step(Emulator<?> emulator, Frame frame) {
        if (frame == null) {
            return initFrame(emulator);
        }

        UnicornPointer sp = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_SP);
        if (frame.fp == null || frame.fp.peer < sp.peer) {
            System.err.println("fp=" + frame.fp + ", sp=" + sp);
            return null;
        }

        UnicornPointer ip = frame.fp.getPointer(4);
        UnicornPointer fp = frame.fp.getPointer(0);
        return createFrame(ip, fp);
    }

}
