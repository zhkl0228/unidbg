package com.github.unidbg.android.ida;

import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;
import unicorn.Arm64Const;

import java.util.Arrays;
import java.util.List;

public class Arm64Register extends UnidbgStructure {

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

    public void fill(Backend backend) {
        for (int reg = Arm64Const.UC_ARM64_REG_X0; reg <= Arm64Const.UC_ARM64_REG_X28; reg++) {
            regs[reg] = readReg(backend, reg);
        }
        regs[29] = readReg(backend, Arm64Const.UC_ARM64_REG_X29);
        regs[30] = readReg(backend, Arm64Const.UC_ARM64_REG_X30);
        sp = readReg(backend, Arm64Const.UC_ARM64_REG_SP);
        pc = readReg(backend, Arm64Const.UC_ARM64_REG_PC);
        pstate = readReg(backend, Arm64Const.UC_ARM64_REG_NZCV);
    }

    static long readReg(Backend backend, int reg) {
        Number number = backend.reg_read(reg);
        return number.longValue();
    }

}
