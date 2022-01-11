package com.github.unidbg;

import capstone.Arm64_const;
import capstone.Arm_const;
import capstone.api.Instruction;
import com.github.unidbg.arm.Cpsr;
import com.github.unidbg.arm.backend.Backend;

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
            if (emulator.is32Bit()) {
                if ((reg >= Arm_const.ARM_REG_R0 && reg <= Arm_const.ARM_REG_R12) ||
                        reg == Arm_const.ARM_REG_LR || reg == Arm_const.ARM_REG_SP ||
                        reg == Arm_const.ARM_REG_CPSR) {
                    if (forWriteRegs) {
                        builder.append(" =>");
                        forWriteRegs = false;
                    }
                    if (reg == Arm_const.ARM_REG_CPSR) {
                        Cpsr cpsr = Cpsr.getArm(backend);
                        builder.append(String.format(Locale.US, " cpsr: N=%d, Z=%d, C=%d, V=%d",
                                cpsr.isNegative() ? 1 : 0,
                                cpsr.isZero() ? 1 : 0,
                                cpsr.hasCarry() ? 1 : 0,
                                cpsr.isOverflow() ? 1 : 0));
                    } else {
                        int value = backend.reg_read(reg).intValue();
                        builder.append(' ').append(instruction.regName(reg)).append("=0x").append(Long.toHexString(value & 0xffffffffL));
                    }
                }
            } else {
                if ((reg >= Arm64_const.ARM64_REG_X0 && reg <= Arm64_const.ARM64_REG_X28) ||
                        (reg >= Arm64_const.ARM64_REG_X29 && reg <= Arm64_const.ARM64_REG_SP)) {
                    if (forWriteRegs) {
                        builder.append(" =>");
                        forWriteRegs = false;
                    }
                    if (reg == Arm64_const.ARM64_REG_NZCV) {
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
                        long value = backend.reg_read(reg).longValue();
                        builder.append(' ').append(instruction.regName(reg)).append("=0x").append(Long.toHexString(value));
                    }
                } else if (reg >= Arm64_const.ARM64_REG_W0 && reg <= Arm64_const.ARM64_REG_W30) {
                    if (forWriteRegs) {
                        builder.append(" =>");
                        forWriteRegs = false;
                    }
                    int value = backend.reg_read(reg).intValue();
                    builder.append(' ').append(instruction.regName(reg)).append("=0x").append(Long.toHexString(value & 0xffffffffL));
                }
            }
        }
    }

}
