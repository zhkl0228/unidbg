package com.github.unidbg.arm;

import capstone.api.Instruction;
import capstone.api.OpShift;
import capstone.api.arm.MemType;
import capstone.api.arm.Operand;
import com.github.unidbg.Alignment;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Utils;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.memory.MemRegion;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import unicorn.Arm64Const;
import unicorn.ArmConst;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * arm utils
 * Created by zhkl0228 on 2017/5/11.
 */

public class ARM {

    public static boolean isThumb(Backend backend) {
        return Cpsr.getArm(backend).isThumb();
    }

    /**
     * 是否为thumb32
     */
    static boolean isThumb32(short ins) {
        return (ins & 0xe000) == 0xe000 && (ins & 0x1800) != 0x0000;
    }

    public static void showThumbRegs(Emulator<?> emulator) {
        showRegs(emulator, ARM.THUMB_REGS);
    }

    public static void showRegs(Emulator<?> emulator, int[] regs) {
        Backend backend = emulator.getBackend();
        boolean thumb = isThumb(backend);
        if (regs == null || regs.length < 1) {
            regs = ARM.getAllRegisters(thumb);
        }
        StringBuilder builder = new StringBuilder();
        builder.append(">>>");
        for (int reg : regs) {
            Number number;
            int value;
            switch (reg) {
                case ArmConst.UC_ARM_REG_CPSR:
                    Cpsr cpsr = Cpsr.getArm(backend);
                    builder.append(String.format(Locale.US, " cpsr: N=%d, Z=%d, C=%d, V=%d, T=%d, mode=0b",
                            cpsr.isNegative() ? 1 : 0,
                            cpsr.isZero() ? 1 : 0,
                            cpsr.hasCarry() ? 1 : 0,
                            cpsr.isOverflow() ? 1 : 0,
                            cpsr.isThumb() ? 1 : 0)).append(Integer.toBinaryString(cpsr.getMode()));
                    break;
                case ArmConst.UC_ARM_REG_R0:
                    number = backend.reg_read(reg);
                    value = number.intValue();
                    builder.append(String.format(Locale.US, " r0=0x%x", value));
                    if (value < 0) {
                        builder.append('(').append(value).append(')');
                    }
                    break;
                case ArmConst.UC_ARM_REG_R1:
                    number = backend.reg_read(reg);
                    value = number.intValue();
                    builder.append(String.format(Locale.US, " r1=0x%x", value));
                    break;
                case ArmConst.UC_ARM_REG_R2:
                    number = backend.reg_read(reg);
                    value = number.intValue();
                    builder.append(String.format(Locale.US, " r2=0x%x", value));
                    break;
                case ArmConst.UC_ARM_REG_R3:
                    number = backend.reg_read(reg);
                    value = number.intValue();
                    builder.append(String.format(Locale.US, " r3=0x%x", value));
                    break;
                case ArmConst.UC_ARM_REG_R4:
                    number = backend.reg_read(reg);
                    value = number.intValue();
                    builder.append(String.format(Locale.US, " r4=0x%x", value));
                    break;
                case ArmConst.UC_ARM_REG_R5:
                    number = backend.reg_read(reg);
                    value = number.intValue();
                    builder.append(String.format(Locale.US, " r5=0x%x", value));
                    break;
                case ArmConst.UC_ARM_REG_R6:
                    number = backend.reg_read(reg);
                    value = number.intValue();
                    builder.append(String.format(Locale.US, " r6=0x%x", value));
                    break;
                case ArmConst.UC_ARM_REG_R7:
                    number = backend.reg_read(reg);
                    value = number.intValue();
                    builder.append(String.format(Locale.US, " r7=0x%x", value));
                    break;
                case ArmConst.UC_ARM_REG_R8:
                    number = backend.reg_read(reg);
                    value = number.intValue();
                    builder.append(String.format(Locale.US, " r8=0x%x", value));
                    break;
                case ArmConst.UC_ARM_REG_R9: // UC_ARM_REG_SB
                    number = backend.reg_read(reg);
                    value = number.intValue();
                    builder.append(String.format(Locale.US, " sb=0x%x", value));
                    break;
                case ArmConst.UC_ARM_REG_R10: // UC_ARM_REG_SL
                    number = backend.reg_read(reg);
                    value = number.intValue();
                    builder.append(String.format(Locale.US, " sl=0x%x", value));
                    break;
                case ArmConst.UC_ARM_REG_FP:
                    number = backend.reg_read(reg);
                    value = number.intValue();
                    builder.append(String.format(Locale.US, " fp=0x%x", value));
                    break;
                case ArmConst.UC_ARM_REG_IP:
                    number = backend.reg_read(reg);
                    value = number.intValue();
                    builder.append(String.format(Locale.US, " ip=0x%x", value));
                    break;
                case ArmConst.UC_ARM_REG_SP:
                    number = backend.reg_read(reg);
                    value = number.intValue();
                    builder.append(String.format(Locale.US, "\n>>> SP=0x%x", value));
                    break;
                case ArmConst.UC_ARM_REG_LR:
                    builder.append(String.format(Locale.US, " LR=%s", UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_LR)));
                    break;
                case ArmConst.UC_ARM_REG_PC:
                    UnidbgPointer pc = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_PC);
                    builder.append(String.format(Locale.US, " PC=%s", pc));
                    break;
                case ArmConst.UC_ARM_REG_D0: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append("\n>>>");
                        builder.append(String.format(Locale.US, " d0=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case ArmConst.UC_ARM_REG_D1: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " d1=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case ArmConst.UC_ARM_REG_D2: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " d2=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case ArmConst.UC_ARM_REG_D3: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " d3=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case ArmConst.UC_ARM_REG_D4: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " d4=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case ArmConst.UC_ARM_REG_D5: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " d5=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case ArmConst.UC_ARM_REG_D6: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " d6=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case ArmConst.UC_ARM_REG_D7: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " d7=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case ArmConst.UC_ARM_REG_D8: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append("\n>>>");
                        builder.append(String.format(Locale.US, " d8=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case ArmConst.UC_ARM_REG_D9: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " d9=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case ArmConst.UC_ARM_REG_D10: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " d10=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case ArmConst.UC_ARM_REG_D11: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " d11=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case ArmConst.UC_ARM_REG_D12: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " d12=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case ArmConst.UC_ARM_REG_D13: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " d13=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case ArmConst.UC_ARM_REG_D14: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " d14=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case ArmConst.UC_ARM_REG_D15:
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " d15=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
            }
        }
        System.out.println(builder);
    }

    public static void showRegs64(Emulator<?> emulator, int[] regs) {
        Backend backend = emulator.getBackend();
        if (regs == null || regs.length < 1) {
            regs = ARM.getAll64Registers();
        }
        StringBuilder builder = new StringBuilder();
        builder.append(">>>");
        for (int reg : regs) {
            Number number;
            long value;
            switch (reg) {
                case Arm64Const.UC_ARM64_REG_NZCV:
                    Cpsr cpsr = Cpsr.getArm64(backend);
                    if (cpsr.isA32()) {
                        builder.append(String.format(Locale.US, " cpsr: N=%d, Z=%d, C=%d, V=%d, T=%d, mode=0b",
                                cpsr.isNegative() ? 1 : 0,
                                cpsr.isZero() ? 1 : 0,
                                cpsr.hasCarry() ? 1 : 0,
                                cpsr.isOverflow() ? 1 : 0,
                                cpsr.isThumb() ? 1 : 0)).append(Integer.toBinaryString(cpsr.getMode()));
                    } else {
                        int el = cpsr.getEL();
                        builder.append(String.format(Locale.US, "\nnzcv: N=%d, Z=%d, C=%d, V=%d, EL%d, use SP_EL",
                                cpsr.isNegative() ? 1 : 0,
                                cpsr.isZero() ? 1 : 0,
                                cpsr.hasCarry() ? 1 : 0,
                                cpsr.isOverflow() ? 1 : 0,
                                el)).append((cpsr.getValue() & 1) == 0 ? 0 : el);
                    }
                    break;
                case Arm64Const.UC_ARM64_REG_X0:
                    number = backend.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x0=0x%x", value));
                    if (value < 0) {
                        builder.append('(').append(value).append(')');
                    } else if((value & 0x7fffffff00000000L) == 0) {
                        int iv = (int) value;
                        if (iv < 0) {
                            builder.append('(').append(iv).append(')');
                        }
                    }
                    break;
                case Arm64Const.UC_ARM64_REG_X1:
                    number = backend.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x1=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X2:
                    number = backend.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x2=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X3:
                    number = backend.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x3=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X4:
                    number = backend.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x4=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X5:
                    number = backend.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x5=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X6:
                    number = backend.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x6=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X7:
                    number = backend.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x7=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X8:
                    number = backend.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x8=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X9:
                    number = backend.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x9=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X10:
                    number = backend.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x10=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X11:
                    number = backend.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x11=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X12:
                    number = backend.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x12=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X13:
                    number = backend.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x13=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X14:
                    number = backend.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x14=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X15:
                    builder.append("\n>>>");
                    number = backend.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x15=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X16:
                    number = backend.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x16=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X17:
                    number = backend.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x17=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X18:
                    number = backend.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x18=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X19:
                    number = backend.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x19=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X20:
                    number = backend.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x20=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X21:
                    number = backend.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x21=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X22:
                    number = backend.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x22=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X23:
                    number = backend.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x23=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X24:
                    number = backend.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x24=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X25:
                    number = backend.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x25=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X26:
                    number = backend.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x26=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X27:
                    number = backend.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x27=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X28:
                    number = backend.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x28=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_FP:
                    number = backend.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " fp=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_SP:
                    number = backend.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, "\nSP=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_LR: {
                    UnidbgPointer lr = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR);
                    builder.append(String.format(Locale.US, "\nLR=%s", lr));
                    break;
                }
                case Arm64Const.UC_ARM64_REG_PC:
                    UnidbgPointer pc = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_PC);
                    builder.append(String.format(Locale.US, "\nPC=%s", pc));
                    break;
                case Arm64Const.UC_ARM64_REG_Q0: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append("\n>>>");
                        builder.append(String.format(Locale.US, " q0=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case Arm64Const.UC_ARM64_REG_Q1: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q1=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case Arm64Const.UC_ARM64_REG_Q2: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q2=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case Arm64Const.UC_ARM64_REG_Q3: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q3=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case Arm64Const.UC_ARM64_REG_Q4: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q4=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case Arm64Const.UC_ARM64_REG_Q5: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q5=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case Arm64Const.UC_ARM64_REG_Q6: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q6=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case Arm64Const.UC_ARM64_REG_Q7: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q7=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case Arm64Const.UC_ARM64_REG_Q8: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q8=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case Arm64Const.UC_ARM64_REG_Q9: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q9=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case Arm64Const.UC_ARM64_REG_Q10: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q10=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case Arm64Const.UC_ARM64_REG_Q11: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q11=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case Arm64Const.UC_ARM64_REG_Q12: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q12=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case Arm64Const.UC_ARM64_REG_Q13: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q13=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case Arm64Const.UC_ARM64_REG_Q14: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q14=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case Arm64Const.UC_ARM64_REG_Q15: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q15=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case Arm64Const.UC_ARM64_REG_Q16: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append("\n>>>");
                        builder.append(String.format(Locale.US, " q16=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case Arm64Const.UC_ARM64_REG_Q17: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q17=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case Arm64Const.UC_ARM64_REG_Q18: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q18=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case Arm64Const.UC_ARM64_REG_Q19: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q19=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case Arm64Const.UC_ARM64_REG_Q20: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q20=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case Arm64Const.UC_ARM64_REG_Q21: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q21=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case Arm64Const.UC_ARM64_REG_Q22: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q22=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case Arm64Const.UC_ARM64_REG_Q23: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q23=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case Arm64Const.UC_ARM64_REG_Q24: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q24=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case Arm64Const.UC_ARM64_REG_Q25: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q25=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case Arm64Const.UC_ARM64_REG_Q26: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q26=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case Arm64Const.UC_ARM64_REG_Q27: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q27=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case Arm64Const.UC_ARM64_REG_Q28: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q28=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case Arm64Const.UC_ARM64_REG_Q29: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q29=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case Arm64Const.UC_ARM64_REG_Q30: {
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q30=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
                }
                case Arm64Const.UC_ARM64_REG_Q31:
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q31=0x%s%s", newBigInteger(data).toString(16), Utils.decodeVectorRegister(data)));
                    }
                    break;
            }
        }
        System.out.println(builder);
    }

    private static BigInteger newBigInteger(byte[] data) {
        if (data.length != 16) {
            throw new IllegalStateException("data.length=" + data.length);
        }
        byte[] copy = Arrays.copyOf(data, data.length);
        for (int i = 0; i < 8; i++) {
            byte b = copy[i];
            copy[i] = copy[15 - i];
            copy[15 - i] = b;
        }
        byte[] bytes = new byte[copy.length + 1];
        System.arraycopy(copy, 0, bytes, 1, copy.length); // makePositive
        return new BigInteger(bytes);
    }

    private static final int[] ARM_ARG_REGS = new int[] {
            ArmConst.UC_ARM_REG_R0,
            ArmConst.UC_ARM_REG_R1,
            ArmConst.UC_ARM_REG_R2,
            ArmConst.UC_ARM_REG_R3
    };

    private static final int[] ARM64_ARG_REGS = new int[] {
            Arm64Const.UC_ARM64_REG_X0,
            Arm64Const.UC_ARM64_REG_X1,
            Arm64Const.UC_ARM64_REG_X2,
            Arm64Const.UC_ARM64_REG_X3,
            Arm64Const.UC_ARM64_REG_X4,
            Arm64Const.UC_ARM64_REG_X5,
            Arm64Const.UC_ARM64_REG_X6,
            Arm64Const.UC_ARM64_REG_X7
    };

    private static final int[] THUMB_REGS = new int[] {
            ArmConst.UC_ARM_REG_R0,
            ArmConst.UC_ARM_REG_R1,
            ArmConst.UC_ARM_REG_R2,
            ArmConst.UC_ARM_REG_R3,
            ArmConst.UC_ARM_REG_R4,
            ArmConst.UC_ARM_REG_R5,
            ArmConst.UC_ARM_REG_R6,
            ArmConst.UC_ARM_REG_R7,
            ArmConst.UC_ARM_REG_R8,
            ArmConst.UC_ARM_REG_SB,
            ArmConst.UC_ARM_REG_SL,

            ArmConst.UC_ARM_REG_FP,
            ArmConst.UC_ARM_REG_IP,

            ArmConst.UC_ARM_REG_SP,
            ArmConst.UC_ARM_REG_LR,
            ArmConst.UC_ARM_REG_PC,
            ArmConst.UC_ARM_REG_CPSR,

            ArmConst.UC_ARM_REG_D0,
            ArmConst.UC_ARM_REG_D1,
            ArmConst.UC_ARM_REG_D2,
            ArmConst.UC_ARM_REG_D3,
            ArmConst.UC_ARM_REG_D4,
            ArmConst.UC_ARM_REG_D5,
            ArmConst.UC_ARM_REG_D6,
            ArmConst.UC_ARM_REG_D7,
            ArmConst.UC_ARM_REG_D8,
            ArmConst.UC_ARM_REG_D9,
            ArmConst.UC_ARM_REG_D10,
            ArmConst.UC_ARM_REG_D11,
            ArmConst.UC_ARM_REG_D12,
            ArmConst.UC_ARM_REG_D13,
            ArmConst.UC_ARM_REG_D14,
            ArmConst.UC_ARM_REG_D15,
    };
    private static final int[] ARM_REGS = new int[] {
            ArmConst.UC_ARM_REG_R0,
            ArmConst.UC_ARM_REG_R1,
            ArmConst.UC_ARM_REG_R2,
            ArmConst.UC_ARM_REG_R3,
            ArmConst.UC_ARM_REG_R4,
            ArmConst.UC_ARM_REG_R5,
            ArmConst.UC_ARM_REG_R6,
            ArmConst.UC_ARM_REG_R7,
            ArmConst.UC_ARM_REG_R8,
            ArmConst.UC_ARM_REG_R9,
            ArmConst.UC_ARM_REG_R10,

            ArmConst.UC_ARM_REG_FP,
            ArmConst.UC_ARM_REG_IP,

            ArmConst.UC_ARM_REG_SP,
            ArmConst.UC_ARM_REG_LR,
            ArmConst.UC_ARM_REG_PC,
            ArmConst.UC_ARM_REG_CPSR,

            ArmConst.UC_ARM_REG_D0,
            ArmConst.UC_ARM_REG_D1,
            ArmConst.UC_ARM_REG_D2,
            ArmConst.UC_ARM_REG_D3,
            ArmConst.UC_ARM_REG_D4,
            ArmConst.UC_ARM_REG_D5,
            ArmConst.UC_ARM_REG_D6,
            ArmConst.UC_ARM_REG_D7,
            ArmConst.UC_ARM_REG_D8,
            ArmConst.UC_ARM_REG_D9,
            ArmConst.UC_ARM_REG_D10,
            ArmConst.UC_ARM_REG_D11,
            ArmConst.UC_ARM_REG_D12,
            ArmConst.UC_ARM_REG_D13,
            ArmConst.UC_ARM_REG_D14,
            ArmConst.UC_ARM_REG_D15,
    };
    private static final int[] ARM64_REGS = new int[] {
            Arm64Const.UC_ARM64_REG_X0,
            Arm64Const.UC_ARM64_REG_X1,
            Arm64Const.UC_ARM64_REG_X2,
            Arm64Const.UC_ARM64_REG_X3,
            Arm64Const.UC_ARM64_REG_X4,
            Arm64Const.UC_ARM64_REG_X5,
            Arm64Const.UC_ARM64_REG_X6,
            Arm64Const.UC_ARM64_REG_X7,
            Arm64Const.UC_ARM64_REG_X8,
            Arm64Const.UC_ARM64_REG_X9,
            Arm64Const.UC_ARM64_REG_X10,
            Arm64Const.UC_ARM64_REG_X11,
            Arm64Const.UC_ARM64_REG_X12,
            Arm64Const.UC_ARM64_REG_X13,
            Arm64Const.UC_ARM64_REG_X14,
            Arm64Const.UC_ARM64_REG_X15,
            Arm64Const.UC_ARM64_REG_X16,
            Arm64Const.UC_ARM64_REG_X17,
            Arm64Const.UC_ARM64_REG_X18,
            Arm64Const.UC_ARM64_REG_X19,
            Arm64Const.UC_ARM64_REG_X20,
            Arm64Const.UC_ARM64_REG_X21,
            Arm64Const.UC_ARM64_REG_X22,
            Arm64Const.UC_ARM64_REG_X23,
            Arm64Const.UC_ARM64_REG_X24,
            Arm64Const.UC_ARM64_REG_X25,
            Arm64Const.UC_ARM64_REG_X26,
            Arm64Const.UC_ARM64_REG_X27,
            Arm64Const.UC_ARM64_REG_X28,

            Arm64Const.UC_ARM64_REG_FP,

            Arm64Const.UC_ARM64_REG_Q0,
            Arm64Const.UC_ARM64_REG_Q1,
            Arm64Const.UC_ARM64_REG_Q2,
            Arm64Const.UC_ARM64_REG_Q3,
            Arm64Const.UC_ARM64_REG_Q4,
            Arm64Const.UC_ARM64_REG_Q5,
            Arm64Const.UC_ARM64_REG_Q6,
            Arm64Const.UC_ARM64_REG_Q7,
            Arm64Const.UC_ARM64_REG_Q8,
            Arm64Const.UC_ARM64_REG_Q9,
            Arm64Const.UC_ARM64_REG_Q10,
            Arm64Const.UC_ARM64_REG_Q11,
            Arm64Const.UC_ARM64_REG_Q12,
            Arm64Const.UC_ARM64_REG_Q13,
            Arm64Const.UC_ARM64_REG_Q14,
            Arm64Const.UC_ARM64_REG_Q15,

            Arm64Const.UC_ARM64_REG_Q16,
            Arm64Const.UC_ARM64_REG_Q17,
            Arm64Const.UC_ARM64_REG_Q18,
            Arm64Const.UC_ARM64_REG_Q19,
            Arm64Const.UC_ARM64_REG_Q20,
            Arm64Const.UC_ARM64_REG_Q21,
            Arm64Const.UC_ARM64_REG_Q22,
            Arm64Const.UC_ARM64_REG_Q23,
            Arm64Const.UC_ARM64_REG_Q24,
            Arm64Const.UC_ARM64_REG_Q25,
            Arm64Const.UC_ARM64_REG_Q26,
            Arm64Const.UC_ARM64_REG_Q27,
            Arm64Const.UC_ARM64_REG_Q28,
            Arm64Const.UC_ARM64_REG_Q29,
            Arm64Const.UC_ARM64_REG_Q30,
            Arm64Const.UC_ARM64_REG_Q31,

            Arm64Const.UC_ARM64_REG_LR,
            Arm64Const.UC_ARM64_REG_SP,
            Arm64Const.UC_ARM64_REG_PC,
            Arm64Const.UC_ARM64_REG_NZCV,
    };

    private static int[] getRegArgs(Emulator<?> emulator) {
        return emulator.is32Bit() ? ARM_ARG_REGS : ARM64_ARG_REGS;
    }

    public static int[] getAllRegisters(boolean thumb) {
        return thumb ? THUMB_REGS : ARM_REGS;
    }

    public static int[] getAll64Registers() {
        return ARM64_REGS;
    }

    private static final int ALIGN_SIZE_BASE = 0x10;

    public static int alignSize(int size) {
        return (int) alignSize(size, ALIGN_SIZE_BASE);
    }

    public static Alignment align(long addr, long size, long alignment) {
        long mask = -alignment;
        long right = addr + size;
        right = (right + alignment - 1) & mask;
        addr &= mask;
        size = right - addr;
        size = (size + alignment - 1) & mask;
        return new Alignment(addr, size);
    }

    public static long alignSize(long size, long align) {
        return ((size - 1) / align + 1) * align;
    }

    static String assembleDetail(Emulator<?> emulator, Instruction ins, long address, boolean thumb, int maxLengthLibraryName) {
        return assembleDetail(emulator, ins, address, thumb, false, maxLengthLibraryName);
    }

    private static void appendMemoryDetails32(Emulator<?> emulator, Instruction ins, capstone.api.arm.OpInfo opInfo, boolean thumb, StringBuilder sb) {
        Memory memory = emulator.getMemory();
        MemType mem = null;
        long addr = -1;
        Operand[] op = opInfo.getOperands();

        // ldr rx, [pc, #0xab] or ldr.w rx, [pc, #0xcd] based capstone.setDetail(Capstone.CS_OPT_ON);
        if (op.length == 2 &&
                op[0].getType() == capstone.Arm_const.ARM_OP_REG &&
                op[1].getType() == capstone.Arm_const.ARM_OP_MEM) {
            mem = op[1].getValue().getMem();

            if (mem.getIndex() == 0 && mem.getScale() == 1 && mem.getLshift() == 0) {
                UnidbgPointer base = UnidbgPointer.register(emulator, ins.mapToUnicornReg(mem.getBase()));
                long base_value = base == null ? 0L : base.peer;
                addr = base_value + mem.getDisp();
            }

            // ldr.w r0, [r2, r0, lsl #2]
            OpShift shift;
            if (mem.getIndex() > 0 && mem.getScale() == 1 && mem.getLshift() == 0 && mem.getDisp() == 0 &&
                    (shift = op[1].getShift()) != null) {
                UnidbgPointer base = UnidbgPointer.register(emulator, ins.mapToUnicornReg(mem.getBase()));
                long base_value = base == null ? 0L : base.peer;
                UnidbgPointer index = UnidbgPointer.register(emulator, ins.mapToUnicornReg(mem.getIndex()));
                int index_value = index == null ? 0 : (int) index.peer;
                if (shift.getType() == capstone.Arm_const.ARM_OP_IMM) {
                    addr = base_value + ((long) index_value << shift.getValue());
                } else if (shift.getType() == capstone.Arm_const.ARM_OP_INVALID) {
                    addr = base_value + index_value;
                }
            }
        }

        // ldrb r0, [r1], #1
        if (op.length == 3 &&
                op[0].getType() == capstone.Arm_const.ARM_OP_REG &&
                op[1].getType() == capstone.Arm_const.ARM_OP_MEM &&
                op[2].getType() == capstone.Arm_const.ARM_OP_IMM) {
            mem = op[1].getValue().getMem();
            if (mem.getIndex() == 0 && mem.getScale() == 1 && mem.getLshift() == 0) {
                UnidbgPointer base = UnidbgPointer.register(emulator, ins.mapToUnicornReg(mem.getBase()));
                addr = base == null ? 0L : base.peer;
            }
        }
        if (addr != -1) {
            if (ins.mapToUnicornReg(mem.getBase()) == ArmConst.UC_ARM_REG_PC) {
                addr += (thumb ? 4 : 8);
            }
            int bytesRead = 4;
            if (ins.getMnemonic().startsWith("ldrb") || ins.getMnemonic().startsWith("strb")) {
                bytesRead = 1;
            }
            if (ins.getMnemonic().startsWith("ldrh") || ins.getMnemonic().startsWith("strh")) {
                bytesRead = 2;
            }
            appendAddrValue(sb, addr, memory, emulator.is64Bit(), bytesRead);
            return;
        }

        // ldrd r2, r1, [r5, #4]
        if ("ldrd".equals(ins.getMnemonic()) && op.length == 3 &&
                op[0].getType() == capstone.Arm_const.ARM_OP_REG &&
                op[1].getType() == capstone.Arm_const.ARM_OP_REG &&
                op[2].getType() == capstone.Arm_const.ARM_OP_MEM) {
            mem = op[2].getValue().getMem();
            if (mem.getIndex() == 0 && mem.getScale() == 1 && mem.getLshift() == 0) {
                int regId = ins.mapToUnicornReg(mem.getBase());
                UnidbgPointer base = UnidbgPointer.register(emulator, regId);
                long base_value = base == null ? 0L : base.peer;
                addr = base_value + mem.getDisp();
                if (regId == ArmConst.UC_ARM_REG_PC) {
                    addr += (thumb ? 4 : 8);
                }
                appendAddrValue(sb, addr, memory, emulator.is64Bit(), 4);
                appendAddrValue(sb, addr + emulator.getPointerSize(), memory, emulator.is64Bit(), 4);
            }
        }
    }

    private static void appendMemoryDetails64(Emulator<?> emulator, Instruction ins, capstone.api.arm64.OpInfo opInfo, StringBuilder sb) {
        Memory memory = emulator.getMemory();
        capstone.api.arm64.MemType mem;
        long addr = -1;
        int bytesRead = 8;
        capstone.api.arm64.Operand[] op = opInfo.getOperands();

        // str w9, [sp, #0xab] based capstone.setDetail(Capstone.CS_OPT_ON);
        if (op.length == 2 &&
                op[0].getType() == capstone.Arm64_const.ARM64_OP_REG &&
                op[1].getType() == capstone.Arm64_const.ARM64_OP_MEM) {
            int regId = ins.mapToUnicornReg(op[0].getValue().getReg());
            if (regId >= Arm64Const.UC_ARM64_REG_W0 && regId <= Arm64Const.UC_ARM64_REG_W30) {
                bytesRead = 4;
            }
            mem = op[1].getValue().getMem();

            if (mem.getIndex() == 0) {
                UnidbgPointer base = UnidbgPointer.register(emulator, ins.mapToUnicornReg(mem.getBase()));
                long base_value = base == null ? 0L : base.peer;
                addr = base_value + mem.getDisp();
            }
        }

        // ldrb r0, [r1], #1
        if (op.length == 3 &&
                op[0].getType() == capstone.Arm64_const.ARM64_OP_REG &&
                op[1].getType() == capstone.Arm64_const.ARM64_OP_MEM &&
                op[2].getType() == capstone.Arm64_const.ARM64_OP_IMM) {
            int regId = ins.mapToUnicornReg(op[0].getValue().getReg());
            if (regId >= Arm64Const.UC_ARM64_REG_W0 && regId <= Arm64Const.UC_ARM64_REG_W30) {
                bytesRead = 4;
            }
            mem = op[1].getValue().getMem();
            if (mem.getIndex() == 0) {
                UnidbgPointer base = UnidbgPointer.register(emulator, ins.mapToUnicornReg(mem.getBase()));
                addr = base == null ? 0L : base.peer;
                addr += mem.getDisp();
            }
        }
        if (addr != -1) {
            if (ins.getMnemonic().startsWith("ldrb") || ins.getMnemonic().startsWith("strb")) {
                bytesRead = 1;
            }
            if (ins.getMnemonic().startsWith("ldrh") || ins.getMnemonic().startsWith("strh")) {
                bytesRead = 2;
            }
            appendAddrValue(sb, addr, memory, emulator.is64Bit(), bytesRead);
        }
    }

    public static void appendHex(StringBuilder builder, long value, int width, char placeholder, boolean reverse) {
        builder.append("0x");
        String hex = Long.toHexString(value);
        appendHex(builder, hex, width, placeholder, reverse);
    }

    public static void appendHex(StringBuilder builder, String str, int width, char placeholder, boolean reverse) {
        if (reverse) {
            builder.append(str);
            for (int i = 0; i < width - str.length(); i++) {
                builder.append(placeholder);
            }
        } else {
            for (int i = 0; i < width - str.length(); i++) {
                builder.append(placeholder);
            }
            builder.append(str);
        }
    }

    public static String assembleDetail(Emulator<?> emulator, Instruction ins, long address, boolean thumb, boolean current, int maxLengthLibraryName) {
        SvcMemory svcMemory = emulator.getSvcMemory();
        MemRegion region = svcMemory.findRegion(address);
        Memory memory = emulator.getMemory();
        char space = current ? '*' : ' ';
        StringBuilder builder = new StringBuilder();
        Module module = region != null ? null : memory.findModuleByAddress(address);
        if (module != null) {
            builder.append('[');
            appendHex(builder, module.name, maxLengthLibraryName, ' ', true);
            builder.append(space);
            appendHex(builder, address - module.base + (thumb ? 1 : 0), Long.toHexString(memory.getMaxSizeOfLibrary()).length(), '0', false);
            builder.append(']').append(space);
        } else if (address >= svcMemory.getBase()) { // kernel
            builder.append('[');
            if (region == null) {
                appendHex(builder, "0x" + Long.toHexString(address), maxLengthLibraryName, ' ', true);
            } else {
                appendHex(builder, region.getName().substring(0, Math.min(maxLengthLibraryName, region.getName().length())), maxLengthLibraryName, ' ', true);
            }
            builder.append(space);
            appendHex(builder, address - svcMemory.getBase() + (thumb ? 1 : 0), Long.toHexString(memory.getMaxSizeOfLibrary()).length(), '0', false);
            builder.append(']').append(space);
        }
        builder.append("[");
        appendHex(builder, Hex.encodeHexString(ins.getBytes()), 8, ' ', true);
        builder.append("]");
        builder.append(space);
        appendHex(builder, ins.getAddress(), 8, '0', false);
        builder.append(":").append(space);
        builder.append('"').append(ins).append('"');

        capstone.api.arm.OpInfo opInfo = null;
        capstone.api.arm64.OpInfo opInfo64 = null;
        if (ins.getOperands() instanceof capstone.api.arm.OpInfo) {
            opInfo = (capstone.api.arm.OpInfo) ins.getOperands();
        }
        if (ins.getOperands() instanceof capstone.api.arm64.OpInfo) {
            opInfo64 = (capstone.api.arm64.OpInfo) ins.getOperands();
        }
        if (current && (ins.getMnemonic().startsWith("ldr") || ins.getMnemonic().startsWith("str")) && opInfo != null) {
            appendMemoryDetails32(emulator, ins, opInfo, thumb, builder);
        }
        if (current && (ins.getMnemonic().startsWith("ldr") || ins.getMnemonic().startsWith("str")) && opInfo64 != null) {
            appendMemoryDetails64(emulator, ins, opInfo64, builder);
        }

        return builder.toString();
    }

    private static void appendAddrValue(StringBuilder sb, long addr, Memory memory, boolean is64Bit, int bytesRead) {
        long mask = -bytesRead;
        Pointer pointer = memory.pointer(addr & mask);
        sb.append(" [0x").append(Long.toHexString(addr)).append(']');
        try {
            if (is64Bit) {
                if (pointer != null) {
                    long value;
                    switch (bytesRead) {
                        case 1:
                            value = pointer.getByte(0) & 0xff;
                            break;
                        case 2:
                            value = pointer.getShort(0) & 0xffff;
                            break;
                        case 4:
                            value = pointer.getInt(0);
                            break;
                        case 8:
                            value = pointer.getLong(0);
                            break;
                        default:
                            throw new IllegalStateException("bytesRead=" + bytesRead);
                    }
                    sb.append(" => 0x").append(Long.toHexString(value));
                    if (value < 0) {
                        sb.append(" (-0x").append(Long.toHexString(-value)).append(')');
                    } else if((value & 0x7fffffff00000000L) == 0) {
                        int iv = (int) value;
                        if (iv < 0) {
                            sb.append(" (-0x").append(Integer.toHexString(-iv)).append(')');
                        }
                    }
                } else {
                    sb.append(" => null");
                }
            } else {
                int value;
                switch (bytesRead) {
                    case 1:
                        value = pointer.getByte(0) & 0xff;
                        break;
                    case 2:
                        value = pointer.getShort(0) & 0xffff;
                        break;
                    case 4:
                        value = pointer.getInt(0);
                        break;
                    default:
                        throw new IllegalStateException("bytesRead=" + bytesRead);
                }
                sb.append(" => 0x").append(Long.toHexString(value & 0xffffffffL));
                if (value < 0) {
                    sb.append(" (-0x").append(Integer.toHexString(-value)).append(")");
                }
            }
        } catch (RuntimeException exception) {
            sb.append(" => ").append(exception.getMessage());
        }
    }

    private static final Logger log = LoggerFactory.getLogger(ARM.class);

    public static void initArgs(Emulator<?> emulator, boolean padding, Number... arguments) {
        Backend backend = emulator.getBackend();
        Memory memory = emulator.getMemory();

        int[] regArgs = ARM.getRegArgs(emulator);
        List<Number> argList = new ArrayList<>(arguments.length * 2);
        int regVector = Arm64Const.UC_ARM64_REG_Q0;
        for (Number arg : arguments) {
            if (emulator.is64Bit()) {
                if (arg instanceof Float) {
                    ByteBuffer buffer = ByteBuffer.allocate(16);
                    buffer.order(ByteOrder.LITTLE_ENDIAN);
                    buffer.putFloat((Float) arg);
                    emulator.getBackend().reg_write_vector(regVector++, buffer.array());
                    continue;
                }
                if (arg instanceof Double) {
                    ByteBuffer buffer = ByteBuffer.allocate(16);
                    buffer.order(ByteOrder.LITTLE_ENDIAN);
                    buffer.putDouble((Double) arg);
                    emulator.getBackend().reg_write_vector(regVector++, buffer.array());
                    continue;
                }
                argList.add(arg);
                continue;
            }
            if (arg instanceof Long) {
                if (log.isDebugEnabled()) {
                    log.debug("initLongArgs size={}, length={}", argList.size(), regArgs.length, new Exception("initArgs long=" + arg));
                }
                if (padding && argList.size() % 2 != 0) {
                    argList.add(0);
                }
                ByteBuffer buffer = ByteBuffer.allocate(8);
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                buffer.putLong((Long) arg);
                buffer.flip();
                int v1 = buffer.getInt();
                int v2 = buffer.getInt();
                argList.add(v1);
                argList.add(v2);
            } else if (arg instanceof Double) {
                if (log.isDebugEnabled()) {
                    log.debug("initDoubleArgs size={}, length={}", argList.size(), regArgs.length, new Exception("initArgs double=" + arg));
                }
                if (padding && argList.size() % 2 != 0) {
                    argList.add(0);
                }
                ByteBuffer buffer = ByteBuffer.allocate(8);
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                buffer.putDouble((Double) arg);
                buffer.flip();
                argList.add(buffer.getInt());
                argList.add(buffer.getInt());
            } else if (arg instanceof Float) {
                if (log.isDebugEnabled()) {
                    log.debug("initFloatArgs size={}, length={}", argList.size(), regArgs.length, new Exception("initArgs float=" + arg));
                }
                ByteBuffer buffer = ByteBuffer.allocate(4);
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                buffer.putFloat((Float) arg);
                buffer.flip();
                argList.add(buffer.getInt());
            } else {
                argList.add(arg);
            }
        }
        final Arguments args = new Arguments(memory, argList.toArray(new Number[0]));

        List<Number> list = new ArrayList<>();
        if (args.args != null) {
            Collections.addAll(list, args.args);
        }
        int i = 0;
        while (!list.isEmpty() && i < regArgs.length) {
            backend.reg_write(regArgs[i], list.remove(0));
            i++;
        }
        Collections.reverse(list);
        if (list.size() % 2 != 0) { // alignment sp
            memory.allocateStack(emulator.getPointerSize());
        }
        while (!list.isEmpty()) {
            Number number = list.remove(0);
            UnidbgPointer pointer = memory.allocateStack(emulator.getPointerSize());
            assert pointer != null;
            if (emulator.is64Bit()) {
                if ((pointer.peer % 8) != 0) {
                    log.warn("init 64BitArgs pointer={}", pointer);
                }
                pointer.setLong(0, number.longValue());
            } else {
                if ((pointer.toUIntPeer() % 4) != 0) {
                    log.warn("init 32BitArgs pointer={}", pointer);
                }
                pointer.setInt(0, number.intValue());
            }
        }
    }

    public static UnidbgPointer adjust_ip(UnidbgPointer ip) {
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

}
