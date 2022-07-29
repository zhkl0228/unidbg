package com.github.unidbg;

import capstone.api.Instruction;
import com.github.unidbg.arm.Cpsr;
import com.github.unidbg.arm.backend.Backend;
import unicorn.Arm64Const;
import unicorn.ArmConst;

import java.util.Locale;

final class RegAccessPrinter {

    private final long address;
    private final Instruction instruction;
    private final short[] accessRegs;
    private boolean forWriteRegs;

    public RegAccessPrinter(long address, Instruction instruction, short[] accessRegs, boolean forWriteRegs) {
        this.address = address;
        this.instruction = instruction;
        this.accessRegs = accessRegs;
        this.forWriteRegs = forWriteRegs;
    }

    public void print(Emulator<?> emulator, Backend backend, StringBuilder builder, long address) {
        if (this.address != address) {
            return;
        }
        for (short reg : accessRegs) {
            int regId = instruction.mapToUnicornReg(reg);
            if (emulator.is32Bit()) {
                if ((regId >= ArmConst.UC_ARM_REG_R0 && regId <= ArmConst.UC_ARM_REG_R12) ||
                        regId == ArmConst.UC_ARM_REG_LR || regId == ArmConst.UC_ARM_REG_SP ||
                        regId == ArmConst.UC_ARM_REG_CPSR) {
                    if (forWriteRegs) {
                        builder.append(" =>");
                        forWriteRegs = false;
                    }
                    if (regId == ArmConst.UC_ARM_REG_CPSR) {
                        Cpsr cpsr = Cpsr.getArm(backend);
                        builder.append(String.format(Locale.US, " cpsr: N=%d, Z=%d, C=%d, V=%d",
                                cpsr.isNegative() ? 1 : 0,
                                cpsr.isZero() ? 1 : 0,
                                cpsr.hasCarry() ? 1 : 0,
                                cpsr.isOverflow() ? 1 : 0));
                    } else {
                        int value = backend.reg_read(regId).intValue();
                        builder.append(' ').append(instruction.regName(reg)).append("=0x").append(Long.toHexString(value & 0xffffffffL));
                    }
                }
            } else {
                if ((regId >= Arm64Const.UC_ARM64_REG_X0 && regId <= Arm64Const.UC_ARM64_REG_X28) ||
                        (regId >= Arm64Const.UC_ARM64_REG_X29 && regId <= Arm64Const.UC_ARM64_REG_SP)) {
                    if (forWriteRegs) {
                        builder.append(" =>");
                        forWriteRegs = false;
                    }
                    if (regId == Arm64Const.UC_ARM64_REG_NZCV) {
                        Cpsr cpsr = Cpsr.getArm64(backend);
                        if (cpsr.isA32()) {
                            builder.append(String.format(Locale.US, " cpsr: N=%d, Z=%d, C=%d, V=%d",
                                    cpsr.isNegative() ? 1 : 0,
                                    cpsr.isZero() ? 1 : 0,
                                    cpsr.hasCarry() ? 1 : 0,
                                    cpsr.isOverflow() ? 1 : 0));
                        } else {
                            builder.append(String.format(Locale.US, " nzcv: N=%d, Z=%d, C=%d, V=%d",
                                    cpsr.isNegative() ? 1 : 0,
                                    cpsr.isZero() ? 1 : 0,
                                    cpsr.hasCarry() ? 1 : 0,
                                    cpsr.isOverflow() ? 1 : 0));
                        }
                    } else {
                        long value = backend.reg_read(regId).longValue();
                        builder.append(' ').append(instruction.regName(reg)).append("=0x").append(Long.toHexString(value));
                    }
                } else if (regId >= Arm64Const.UC_ARM64_REG_W0 && regId <= Arm64Const.UC_ARM64_REG_W30) {
                    if (forWriteRegs) {
                        builder.append(" =>");
                        forWriteRegs = false;
                    }
                    int value = backend.reg_read(regId).intValue();
                    builder.append(' ').append(instruction.regName(reg)).append("=0x").append(Long.toHexString(value & 0xffffffffL));
                }
            }
        }
    }

}
