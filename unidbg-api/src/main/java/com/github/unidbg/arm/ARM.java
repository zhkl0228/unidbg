package com.github.unidbg.arm;

import capstone.Arm;
import capstone.Arm_const;
import capstone.Capstone;
import com.github.unidbg.Alignment;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;
import unicorn.ArmConst;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
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
                    builder.append(String.format(Locale.US, " SP=0x%x", value));
                    break;
                case ArmConst.UC_ARM_REG_LR:
                    builder.append(String.format(Locale.US, " LR=%s", UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_LR)));
                    break;
                case ArmConst.UC_ARM_REG_PC:
                    builder.append(String.format(Locale.US, " PC=%s", UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_PC)));
                    break;
                case ArmConst.UC_ARM_REG_Q0:
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append("\n>>>");
                        builder.append(String.format(Locale.US, " q0=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case ArmConst.UC_ARM_REG_Q1:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q1=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case ArmConst.UC_ARM_REG_Q2:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q2=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case ArmConst.UC_ARM_REG_Q3:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q3=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case ArmConst.UC_ARM_REG_Q4:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q4=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case ArmConst.UC_ARM_REG_Q5:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q5=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case ArmConst.UC_ARM_REG_Q6:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q6=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case ArmConst.UC_ARM_REG_Q7:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q7=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case ArmConst.UC_ARM_REG_Q8:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q8=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case ArmConst.UC_ARM_REG_Q9:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q9=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case ArmConst.UC_ARM_REG_Q10:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q10=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case ArmConst.UC_ARM_REG_Q11:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q11=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case ArmConst.UC_ARM_REG_Q12:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q12=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case ArmConst.UC_ARM_REG_Q13:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q13=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case ArmConst.UC_ARM_REG_Q14:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q14=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case ArmConst.UC_ARM_REG_Q15:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q15=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
            }
        }
        System.out.println(builder.toString());
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
                case Arm64Const.UC_ARM64_REG_LR:
                    builder.append(String.format(Locale.US, "\nLR=%s", UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR)));
                    break;
                case Arm64Const.UC_ARM64_REG_PC:
                    builder.append(String.format(Locale.US, "\nPC=%s", UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_PC)));
                    break;
                case Arm64Const.UC_ARM64_REG_Q0:
                    byte[] data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append("\n>>>");
                        builder.append(String.format(Locale.US, " q0=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case Arm64Const.UC_ARM64_REG_Q1:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q1=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case Arm64Const.UC_ARM64_REG_Q2:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q2=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case Arm64Const.UC_ARM64_REG_Q3:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q3=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case Arm64Const.UC_ARM64_REG_Q4:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q4=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case Arm64Const.UC_ARM64_REG_Q5:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q5=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case Arm64Const.UC_ARM64_REG_Q6:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q6=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case Arm64Const.UC_ARM64_REG_Q7:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q7=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case Arm64Const.UC_ARM64_REG_Q8:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q8=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case Arm64Const.UC_ARM64_REG_Q9:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q9=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case Arm64Const.UC_ARM64_REG_Q10:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q10=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case Arm64Const.UC_ARM64_REG_Q11:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q11=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case Arm64Const.UC_ARM64_REG_Q12:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q12=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case Arm64Const.UC_ARM64_REG_Q13:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q13=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case Arm64Const.UC_ARM64_REG_Q14:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q14=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case Arm64Const.UC_ARM64_REG_Q15:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q15=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case Arm64Const.UC_ARM64_REG_Q16:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append("\n>>>");
                        builder.append(String.format(Locale.US, " q16=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case Arm64Const.UC_ARM64_REG_Q17:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q17=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case Arm64Const.UC_ARM64_REG_Q18:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q18=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case Arm64Const.UC_ARM64_REG_Q19:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q19=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case Arm64Const.UC_ARM64_REG_Q20:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q20=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case Arm64Const.UC_ARM64_REG_Q21:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q21=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case Arm64Const.UC_ARM64_REG_Q22:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q22=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case Arm64Const.UC_ARM64_REG_Q23:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q23=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case Arm64Const.UC_ARM64_REG_Q24:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q24=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case Arm64Const.UC_ARM64_REG_Q25:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q25=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case Arm64Const.UC_ARM64_REG_Q26:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q26=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case Arm64Const.UC_ARM64_REG_Q27:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q27=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case Arm64Const.UC_ARM64_REG_Q28:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q28=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case Arm64Const.UC_ARM64_REG_Q29:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q29=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case Arm64Const.UC_ARM64_REG_Q30:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q30=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
                case Arm64Const.UC_ARM64_REG_Q31:
                    data = backend.reg_read_vector(reg);
                    if (data != null) {
                        builder.append(String.format(Locale.US, " q31=0x%s", newBigInteger(data).toString(16)));
                    }
                    break;
            }
        }
        System.out.println(builder.toString());
    }

    private static BigInteger newBigInteger(byte[] data) {
        if (data.length != 16) {
            throw new IllegalStateException("data.length=" + data.length);
        }
        for (int i = 0; i < 8; i++) {
            byte b = data[i];
            data[i] = data[15 - i];
            data[15 - i] = b;
        }
        byte[] bytes = new byte[data.length + 1];
        System.arraycopy(data, 0, bytes, 1, data.length); // makePositive
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

            /*ArmConst.UC_ARM_REG_Q0,
            ArmConst.UC_ARM_REG_Q1,
            ArmConst.UC_ARM_REG_Q2,
            ArmConst.UC_ARM_REG_Q3,
            ArmConst.UC_ARM_REG_Q4,
            ArmConst.UC_ARM_REG_Q5,
            ArmConst.UC_ARM_REG_Q6,
            ArmConst.UC_ARM_REG_Q7,
            ArmConst.UC_ARM_REG_Q8,
            ArmConst.UC_ARM_REG_Q9,
            ArmConst.UC_ARM_REG_Q10,
            ArmConst.UC_ARM_REG_Q11,
            ArmConst.UC_ARM_REG_Q12,
            ArmConst.UC_ARM_REG_Q13,
            ArmConst.UC_ARM_REG_Q14,
            ArmConst.UC_ARM_REG_Q15,*/
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

    public static String readCString(Backend backend, long address) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(0x1000);
        int size = 0;
        try {
            while (true) {
                byte[] oneByte = backend.mem_read(address, 1);
                size += oneByte.length;

                if (size > 0x1000) {
                    throw new IllegalStateException("read utf8 string failed");
                }

                if (oneByte[0] == 0) {
                    break;
                }
                baos.write(oneByte);
                address += oneByte.length;
            }

            return baos.toString("UTf-8");
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    static String assembleDetail(Emulator<?> emulator, Capstone.CsInsn ins, long address, boolean thumb) {
        return assembleDetail(emulator, ins, address, thumb, false);
    }

    private static void appendMemoryDetails32(Emulator<?> emulator, Capstone.CsInsn ins, Arm.OpInfo opInfo, boolean thumb, StringBuilder sb) {
        Memory memory = emulator.getMemory();
        Arm.MemType mem = null;
        long addr = -1;

        // ldr rx, [pc, #0xab] or ldr.w rx, [pc, #0xcd] based capstone.setDetail(Capstone.CS_OPT_ON);
        if (opInfo.op.length == 2 &&
                opInfo.op[0].type == Arm_const.ARM_OP_REG &&
                opInfo.op[1].type == Arm_const.ARM_OP_MEM) {
            mem = opInfo.op[1].value.mem;

            if (mem.index == 0 && mem.scale == 1 && mem.lshift == 0) {
                UnidbgPointer base = UnidbgPointer.register(emulator, mem.base);
                long base_value = base == null ? 0L : base.peer;
                addr = base_value + mem.disp;
            }

            // ldr.w r0, [r2, r0, lsl #2]
            Arm.OpShift shift;
            if (mem.index > 0 && mem.scale == 1 && mem.lshift == 0 && mem.disp == 0 &&
                    (shift = opInfo.op[1].shift) != null) {
                UnidbgPointer base = UnidbgPointer.register(emulator, mem.base);
                long base_value = base == null ? 0L : base.peer;
                UnidbgPointer index = UnidbgPointer.register(emulator, mem.index);
                int index_value = index == null ? 0 : (int) index.peer;
                if (shift.type == Arm_const.ARM_OP_IMM) {
                    addr = base_value + (index_value << shift.value);
                } else if (shift.type == Arm_const.ARM_OP_INVALID) {
                    addr = base_value + index_value;
                }
            }
        }

        // ldrb r0, [r1], #1
        if (opInfo.op.length == 3 &&
                opInfo.op[0].type == Arm_const.ARM_OP_REG &&
                opInfo.op[1].type == Arm_const.ARM_OP_MEM &&
                opInfo.op[2].type == Arm_const.ARM_OP_IMM) {
            mem = opInfo.op[1].value.mem;
            if (mem.index == 0 && mem.scale == 1 && mem.lshift == 0) {
                UnidbgPointer base = UnidbgPointer.register(emulator, mem.base);
                addr = base == null ? 0L : base.peer;
            }
        }
        if (addr != -1) {
            if (mem.base == Arm_const.ARM_REG_PC) {
                addr += (thumb ? 4 : 8);
            }
            int bytesRead = 4;
            if (ins.mnemonic.startsWith("ldrb") || ins.mnemonic.startsWith("strb")) {
                bytesRead = 1;
            }
            if (ins.mnemonic.startsWith("ldrh") || ins.mnemonic.startsWith("strh")) {
                bytesRead = 2;
            }
            appendAddrValue(sb, addr, memory, emulator.is64Bit(), bytesRead);
            return;
        }

        // ldrd r2, r1, [r5, #4]
        if ("ldrd".equals(ins.mnemonic) && opInfo.op.length == 3 &&
                opInfo.op[0].type == Arm_const.ARM_OP_REG &&
                opInfo.op[1].type == Arm_const.ARM_OP_REG &&
                opInfo.op[2].type == Arm_const.ARM_OP_MEM) {
            mem = opInfo.op[2].value.mem;
            if (mem.index == 0 && mem.scale == 1 && mem.lshift == 0) {
                UnidbgPointer base = UnidbgPointer.register(emulator, mem.base);
                long base_value = base == null ? 0L : base.peer;
                addr = base_value + mem.disp;
                if (mem.base == Arm_const.ARM_REG_PC) {
                    addr += (thumb ? 4 : 8);
                }
                appendAddrValue(sb, addr, memory, emulator.is64Bit(), 4);
                appendAddrValue(sb, addr + emulator.getPointerSize(), memory, emulator.is64Bit(), 4);
            }
        }
    }

    public static String assembleDetail(Emulator<?> emulator, Capstone.CsInsn ins, long address, boolean thumb, boolean current) {
        Memory memory = emulator.getMemory();
        char space = current ? '*' : ' ';
        StringBuilder sb = new StringBuilder();
        Module module = memory.findModuleByAddress(address);
        String maxLengthSoName = memory.getMaxLengthLibraryName();
        if (module != null) {
            sb.append(String.format("[%" + maxLengthSoName.length() + "s]", module.name)).append(space);
            sb.append(String.format("[0x%0" + Long.toHexString(memory.getMaxSizeOfLibrary()).length() + "x]", address - module.base + (thumb ? 1 : 0))).append(space);
        } else if (address >= 0xfffe0000L && maxLengthSoName != null) { // kernel
            sb.append(String.format("[%" + maxLengthSoName.length() + "s]", "0x" + Long.toHexString(address))).append(space);
            sb.append(String.format("[0x%0" + Long.toHexString(memory.getMaxSizeOfLibrary()).length() + "x]", address - 0xfffe0000L + (thumb ? 1 : 0))).append(space);
        }
        sb.append("[");
        if (ins.size == 2) {
            sb.append(space).append("     ");
        }
        for (byte b : ins.bytes) {
            sb.append(' ');
            String hex = Integer.toHexString(b & 0xff);
            if (hex.length() == 1) {
                sb.append(0);
            }
            sb.append(hex);
        }
        sb.append(" ]").append(space);
        sb.append(String.format("0x%08x:" + space + "%s %s", ins.address, ins.mnemonic, ins.opStr));

        Arm.OpInfo opInfo = null;
        if (ins.operands instanceof Arm.OpInfo) {
            opInfo = (Arm.OpInfo) ins.operands;
        }
        if (current && (ins.mnemonic.startsWith("ldr") || ins.mnemonic.startsWith("str")) && opInfo != null) {
            appendMemoryDetails32(emulator, ins, opInfo, thumb, sb);
        }

        return sb.toString();
    }

    private static void appendAddrValue(StringBuilder sb, long addr, Memory memory, boolean is64Bit, int bytesRead) {
        long mask = -bytesRead;
        Pointer pointer = memory.pointer(addr & mask);
        sb.append(" [0x").append(Long.toHexString(addr)).append(']');
        try {
            if (is64Bit) {
                long value = pointer.getLong(0);
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
        } catch (BackendException exception) {
            sb.append(" => ").append(exception.getMessage());
        }
    }

    private static final Log log = LogFactory.getLog(ARM.class);

    static Arguments initArgs(Emulator<?> emulator, boolean padding, Number... arguments) {
        Backend backend = emulator.getBackend();
        Memory memory = emulator.getMemory();

        int[] regArgs = ARM.getRegArgs(emulator);
        List<Number> argList = new ArrayList<>(arguments.length * 2);
        int index = 0;
        for (Number arg : arguments) {
            if (emulator.is64Bit()) {
                argList.add(arg);
                continue;
            }
            if (arg instanceof Long) {
                if (log.isDebugEnabled()) {
                    log.debug("initLongArgs index=" + index + ", length=" + regArgs.length, new Exception("initArgs long=" + arg));
                }
                if (padding && index == regArgs.length - 1) {
                    argList.add(0);
                    index++;
                }
                ByteBuffer buffer = ByteBuffer.allocate(8);
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                buffer.putLong((Long) arg);
                buffer.flip();
                int v1 = buffer.getInt();
                int v2 = buffer.getInt();
                argList.add(v1);
                argList.add(v2);
                index += 2;
            } else if (arg instanceof Double) {
                if (log.isDebugEnabled()) {
                    log.debug("initDoubleArgs index=" + index + ", length=" + regArgs.length, new Exception("initArgs double=" + arg));
                }
                if (padding && index == regArgs.length - 1) {
                    argList.add(0);
                    index++;
                }
                ByteBuffer buffer = ByteBuffer.allocate(8);
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                buffer.putDouble((Double) arg);
                buffer.flip();
                argList.add(buffer.getInt());
                argList.add(buffer.getInt());
                index += 2;
            } else if (arg instanceof Float) {
                if (log.isDebugEnabled()) {
                    log.debug("initFloatArgs index=" + index + ", length=" + regArgs.length, new Exception("initArgs float=" + arg));
                }
                ByteBuffer buffer = ByteBuffer.allocate(4);
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                buffer.putFloat((Float) arg);
                buffer.flip();
                argList.add(buffer.getInt());
                index++;
            } else {
                argList.add(arg);
                index++;
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
                    log.warn("initArgs pointer=" + pointer);
                }
                pointer.setLong(0, number.longValue());
            } else {
                if ((pointer.toUIntPeer() % 4) != 0) {
                    log.warn("initArgs pointer=" + pointer);
                }
                pointer.setInt(0, number.intValue());
            }
        }
        return args;
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
