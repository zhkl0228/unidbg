package com.github.unidbg.unwind;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.AbstractARMEmulator;
import com.github.unidbg.pointer.UnidbgPointer;
import unicorn.ArmConst;

public class SimpleARMUnwinder extends Unwinder {

    public SimpleARMUnwinder(Emulator<?> emulator) {
        super(emulator);
    }

    @Override
    protected String getBaseFormat() {
        return "[0x%08x]";
    }

    @Override
    public Frame createFrame(UnidbgPointer ip, UnidbgPointer fp) {
        if (ip != null) {
            if (ip.peer == AbstractARMEmulator.LR) {
                return new Frame(ip, null);
            }

            return new Frame(adjust_ip(ip), fp);
        } else {
            return null;
        }
    }

    private UnidbgPointer adjust_ip(UnidbgPointer ip) {
        int adjust = 4;

        boolean thumb = (ip.peer & 1) == 1;
        if (thumb) {
            /* Thumb instructions, the currently executing instruction could be
             * 2 or 4 bytes, so adjust appropriately.
             */
            int value = ip.share(-5).getInt(0);
            if ((value & 0xe000f000L) != 0xe000f000L) {
                adjust = 2;
            }
        }

        return ip.share(-adjust, 0);
    }

    private Frame initFrame(Emulator<?> emulator) {
        UnidbgPointer ip = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_LR);
        UnidbgPointer fp = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R7);
        return createFrame(ip, fp);
    }

    @Override
    protected Frame unw_step(Emulator<?> emulator, Frame frame) {
        if (frame == null) {
            return initFrame(emulator);
        }

        UnidbgPointer sp = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_SP);
        if (frame.fp == null || frame.fp.peer < sp.peer) {
            System.err.println("fp=" + frame.fp + ", sp=" + sp);
            return null;
        }

        UnidbgPointer ip = frame.fp.getPointer(4);
        UnidbgPointer fp = frame.fp.getPointer(0);
        return createFrame(ip, fp);
    }

}
