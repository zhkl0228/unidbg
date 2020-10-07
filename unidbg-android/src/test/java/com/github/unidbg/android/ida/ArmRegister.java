package com.github.unidbg.android.ida;

import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;
import unicorn.ArmConst;

import java.util.Arrays;
import java.util.List;

public class ArmRegister extends UnidbgStructure {

    public ArmRegister(Pointer p) {
        super(p);
    }

    public int ARM_r0;
    public int ARM_r1;
    public int ARM_r2;
    public int ARM_r3;
    public int ARM_r4;
    public int ARM_r5;
    public int ARM_r6;
    public int ARM_r7;
    public int ARM_r8;
    public int ARM_r9;
    public int ARM_r10;

    public int ARM_fp;
    public int ARM_ip;
    public int ARM_sp;
    public int ARM_lr;
    public int ARM_pc;
    public int ARM_cpsr;
    public int ARM_ORIG_r0;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("ARM_r0", "ARM_r1", "ARM_r2", "ARM_r3", "ARM_r4", "ARM_r5", "ARM_r6", "ARM_r7", "ARM_r8", "ARM_r9", "ARM_r10",
                "ARM_fp", "ARM_ip", "ARM_sp", "ARM_lr", "ARM_pc", "ARM_cpsr", "ARM_ORIG_r0");
    }

    public void fill(Backend backend) {
        ARM_r0 = readReg(backend, ArmConst.UC_ARM_REG_R0);
        ARM_r1 = readReg(backend, ArmConst.UC_ARM_REG_R1);
        ARM_r2 = readReg(backend, ArmConst.UC_ARM_REG_R2);
        ARM_r3 = readReg(backend, ArmConst.UC_ARM_REG_R3);
        ARM_r4 = readReg(backend, ArmConst.UC_ARM_REG_R4);
        ARM_r5 = readReg(backend, ArmConst.UC_ARM_REG_R5);
        ARM_r6 = readReg(backend, ArmConst.UC_ARM_REG_R6);
        ARM_r7 = readReg(backend, ArmConst.UC_ARM_REG_R7);
        ARM_r8 = readReg(backend, ArmConst.UC_ARM_REG_R8);
        ARM_r9 = readReg(backend, ArmConst.UC_ARM_REG_R9);
        ARM_r10 = readReg(backend, ArmConst.UC_ARM_REG_R10);

        ARM_fp = readReg(backend, ArmConst.UC_ARM_REG_FP);
        ARM_ip = readReg(backend, ArmConst.UC_ARM_REG_IP);
        ARM_sp = readReg(backend, ArmConst.UC_ARM_REG_SP);
        ARM_lr = readReg(backend, ArmConst.UC_ARM_REG_LR);
        ARM_pc = readReg(backend, ArmConst.UC_ARM_REG_PC);
        ARM_cpsr = readReg(backend, ArmConst.UC_ARM_REG_CPSR);
        ARM_ORIG_r0 = -1;
    }

    static int readReg(Backend backend, int reg) {
        Number number = backend.reg_read(reg);
        return number.intValue();
    }

}
