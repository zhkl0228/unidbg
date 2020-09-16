package com.github.unidbg.android.ida;

import com.github.unidbg.pointer.UnicornStructure;
import com.sun.jna.Pointer;
import unicorn.Arm64Const;
import unicorn.Unicorn;

import java.util.Arrays;
import java.util.List;

public class Arm64Register extends UnicornStructure {

    public Arm64Register(Pointer p) {
        super(p);
    }

    public long[] regs = new long[31];
    public long sp;
    public long pc;
    public long pstate;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("regs", "sp", "pc", "pstate");
    }

    public void fill(Unicorn u) {
        for (int i = 0; i < 29; i++) {
            int reg = Arm64Const.UC_ARM64_REG_X0 + i;
            regs[i] = readReg(u, reg);
        }
        regs[29] = readReg(u, Arm64Const.UC_ARM64_REG_X29);
        regs[30] = readReg(u, Arm64Const.UC_ARM64_REG_X30);
        sp = readReg(u, Arm64Const.UC_ARM64_REG_SP);
        pc = readReg(u, Arm64Const.UC_ARM64_REG_PC);
        pstate = readReg(u, Arm64Const.UC_ARM64_REG_NZCV);
    }

    static long readReg(Unicorn u, int reg) {
        Number number = (Number) u.reg_read(reg);
        return number.longValue();
    }

}
