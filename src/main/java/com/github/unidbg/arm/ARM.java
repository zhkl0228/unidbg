package com.github.unidbg.arm;

import capstone.Arm;
import capstone.Arm_const;
import capstone.Capstone;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;
import unicorn.ArmConst;
import unicorn.Unicorn;
import unicorn.UnicornException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * arm utils
 * Created by zhkl0228 on 2017/5/11.
 */

public class ARM {

    public static boolean isThumb(Unicorn unicorn) {
        return Cpsr.getArm(unicorn).isThumb();
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
        Unicorn unicorn = emulator.getUnicorn();
        boolean thumb = isThumb(unicorn);
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
                    Cpsr cpsr = Cpsr.getArm(unicorn);
                    builder.append(String.format(Locale.US, " cpsr: N=%d, Z=%d, C=%d, V=%d, T=%d, mode=0b",
                            cpsr.isNegative() ? 1 : 0,
                            cpsr.isZero() ? 1 : 0,
                            cpsr.hasCarry() ? 1 : 0,
                            cpsr.isOverflow() ? 1 : 0,
                            cpsr.isThumb() ? 1 : 0)).append(Integer.toBinaryString(cpsr.getMode()));
                    break;
                case ArmConst.UC_ARM_REG_R0:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.intValue();
                    builder.append(String.format(Locale.US, " r0=0x%x", value));
                    if (value < 0) {
                        builder.append('(').append(value).append(')');
                    }
                    break;
                case ArmConst.UC_ARM_REG_R1:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.intValue();
                    builder.append(String.format(Locale.US, " r1=0x%x", value));
                    break;
                case ArmConst.UC_ARM_REG_R2:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.intValue();
                    builder.append(String.format(Locale.US, " r2=0x%x", value));
                    break;
                case ArmConst.UC_ARM_REG_R3:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.intValue();
                    builder.append(String.format(Locale.US, " r3=0x%x", value));
                    break;
                case ArmConst.UC_ARM_REG_R4:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.intValue();
                    builder.append(String.format(Locale.US, " r4=0x%x", value));
                    break;
                case ArmConst.UC_ARM_REG_R5:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.intValue();
                    builder.append(String.format(Locale.US, " r5=0x%x", value));
                    break;
                case ArmConst.UC_ARM_REG_R6:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.intValue();
                    builder.append(String.format(Locale.US, " r6=0x%x", value));
                    break;
                case ArmConst.UC_ARM_REG_R7:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.intValue();
                    builder.append(String.format(Locale.US, " r7=0x%x", value));
                    break;
                case ArmConst.UC_ARM_REG_R8:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.intValue();
                    builder.append(String.format(Locale.US, " r8=0x%x", value));
                    break;
                case ArmConst.UC_ARM_REG_R9: // UC_ARM_REG_SB
                    number = (Number) unicorn.reg_read(reg);
                    value = number.intValue();
                    builder.append(String.format(Locale.US, " sb=0x%x", value));
                    break;
                case ArmConst.UC_ARM_REG_R10: // UC_ARM_REG_SL
                    number = (Number) unicorn.reg_read(reg);
                    value = number.intValue();
                    builder.append(String.format(Locale.US, " sl=0x%x", value));
                    break;
                case ArmConst.UC_ARM_REG_FP:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.intValue();
                    builder.append(String.format(Locale.US, " fp=0x%x", value));
                    break;
                case ArmConst.UC_ARM_REG_IP:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.intValue();
                    builder.append(String.format(Locale.US, " ip=0x%x", value));
                    break;
                case ArmConst.UC_ARM_REG_SP:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.intValue();
                    builder.append(String.format(Locale.US, " SP=0x%x", value));
                    break;
                case ArmConst.UC_ARM_REG_LR:
                    builder.append(String.format(Locale.US, " LR=%s", UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR)));
                    break;
                case ArmConst.UC_ARM_REG_PC:
                    builder.append(String.format(Locale.US, " PC=%s", UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_PC)));
                    break;
            }
        }
        System.out.println(builder.toString());
    }

    public static void showRegs64(Emulator<?> emulator, int[] regs) {
        Unicorn unicorn = emulator.getUnicorn();
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
                    Cpsr cpsr = Cpsr.getArm64(unicorn);
                    builder.append(String.format(Locale.US, "\nnzcv: N=%d, Z=%d, C=%d, V=%d, T=%d, mode=0b",
                            cpsr.isNegative() ? 1 : 0,
                            cpsr.isZero() ? 1 : 0,
                            cpsr.hasCarry() ? 1 : 0,
                            cpsr.isOverflow() ? 1 : 0,
                            cpsr.isThumb() ? 1 : 0)).append(Integer.toBinaryString(cpsr.getMode()));
                    break;
                case Arm64Const.UC_ARM64_REG_X0:
                    number = (Number) unicorn.reg_read(reg);
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
                    number = (Number) unicorn.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x1=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X2:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x2=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X3:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x3=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X4:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x4=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X5:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x5=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X6:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x6=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X7:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x7=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X8:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x8=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X9:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x9=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X10:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x10=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X11:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x11=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X12:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x12=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X13:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x13=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X14:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x14=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X15:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x15=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X16:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x16=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X17:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x17=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X18:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x18=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X19:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x19=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X20:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x20=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X21:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x21=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X22:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x22=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X23:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x23=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X24:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x24=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X25:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x25=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X26:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x26=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X27:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x27=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_X28:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " x28=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_FP:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, " fp=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_SP:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, "\nSP=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_LR:
                    builder.append(String.format(Locale.US, "\nLR=%s", UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR)));
                    break;
                case Arm64Const.UC_ARM64_REG_PC:
                    builder.append(String.format(Locale.US, "\nPC=%s", UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_PC)));
                    break;
            }
        }
        System.out.println(builder.toString());
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
            ArmConst.UC_ARM_REG_CPSR
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
            ArmConst.UC_ARM_REG_CPSR
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
            Arm64Const.UC_ARM64_REG_LR,
            Arm64Const.UC_ARM64_REG_SP,
            Arm64Const.UC_ARM64_REG_PC,
            Arm64Const.UC_ARM64_REG_NZCV
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

    public static long alignSize(long size, long align) {
        return ((size - 1) / align + 1) * align;
    }

    public static String readCString(Unicorn unicorn, long address) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(0x1000);
        int size = 0;
        try {
            while (true) {
                byte[] oneByte = unicorn.mem_read(address, 1);
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

    private static final Pattern MEM_PATTERN = Pattern.compile("\\w+,\\s\\[(\\w+),\\s#(-)?(0x)?(\\w+)]");

    static String assembleDetail(Emulator<?> emulator, Capstone.CsInsn ins, long address, boolean thumb) {
        return assembleDetail(emulator, ins, address, thumb, false);
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

        Arm.OpInfo opInfo = (Arm.OpInfo) ins.operands;
        if (ins.mnemonic.startsWith("ldr") || ins.mnemonic.startsWith("str")) {
            Matcher matcher;

            // ldr rx, [pc, #0xab] or ldr.w rx, [pc, #0xcd] based capstone.setDetail(Capstone.CS_OPT_ON);
            if (opInfo != null &&
                    opInfo.op.length == 2 &&
                    opInfo.op[0].type == Arm_const.ARM_OP_REG &&
                    opInfo.op[1].type == Arm_const.ARM_OP_MEM) {
                Arm.MemType mem = opInfo.op[1].value.mem;
                if (mem.base == Arm_const.ARM_REG_PC && mem.index == 0 && mem.scale == 1 && mem.lshift == 0) {
                    long addr = ins.address + mem.disp;
                    addr += (thumb ? 4 : 8);
                    appendAddrValue(sb, addr, memory, emulator.is64Bit());
                }
            } else if((matcher = MEM_PATTERN.matcher(ins.opStr)).find()) {
                String reg = matcher.group(1);
                boolean minus = "-".equals(matcher.group(2));
                String g1 = matcher.group(3);
                boolean hex = "0x".equals(g1);
                String g2 = matcher.group(4);
                long value = hex ? Long.parseLong(g2, 16) : Long.parseLong(g2);
                if (minus) {
                    value = -value;
                }
                if ("pc".equals(reg)) {
                    long addr = ins.address + value;
                    addr += (thumb ? 4 : 8);
                    appendAddrValue(sb, addr, memory, emulator.is64Bit());
                } else if (current) {
                    boolean is64Bit = emulator.is64Bit();
                    int r = -1;
                    switch (reg) {
                        case "r0":
                            r = ArmConst.UC_ARM_REG_R0;
                            break;
                        case "r1":
                            r = ArmConst.UC_ARM_REG_R1;
                            break;
                        case "r2":
                            r = ArmConst.UC_ARM_REG_R2;
                            break;
                        case "r3":
                            r = ArmConst.UC_ARM_REG_R3;
                            break;
                        case "r4":
                            r = ArmConst.UC_ARM_REG_R4;
                            break;
                        case "r5":
                            r = ArmConst.UC_ARM_REG_R5;
                            break;
                        case "r6":
                            r = ArmConst.UC_ARM_REG_R6;
                            break;
                        case "r7":
                            r = ArmConst.UC_ARM_REG_R7;
                            break;
                        case "x0":
                            r = Arm64Const.UC_ARM64_REG_X0;
                            break;
                        case "x8":
                            r = Arm64Const.UC_ARM64_REG_X8;
                            break;
                        case "x19":
                            r = Arm64Const.UC_ARM64_REG_X19;
                            break;
                        case "x20":
                            r = Arm64Const.UC_ARM64_REG_X20;
                            break;
                        case "x21":
                            r = Arm64Const.UC_ARM64_REG_X21;
                            break;
                        case "fp":
                            r = is64Bit ? Arm64Const.UC_ARM64_REG_FP : ArmConst.UC_ARM_REG_FP;
                            break;
                        case "sp":
                            r = is64Bit ? Arm64Const.UC_ARM64_REG_SP : ArmConst.UC_ARM_REG_SP;
                            break;
                        case "lr":
                            r = is64Bit ? Arm64Const.UC_ARM64_REG_LR : ArmConst.UC_ARM_REG_LR;
                            break;
                    }
                    if (r != -1) {
                        UnicornPointer pointer = UnicornPointer.register(emulator, r);
                        if (pointer != null) {
                            long addr = (is64Bit ? pointer.peer : pointer.toUIntPeer()) + value;
                            appendAddrValue(sb, addr, memory, is64Bit);
                        }
                    }
                }
            }
        }

        return sb.toString();
    }

    private static void appendAddrValue(StringBuilder sb, long addr, Memory memory, boolean is64Bit) {
        Pointer pointer = memory.pointer(addr & 0xfffffffffffffffcL);
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
                int value = pointer.getInt(0);
                sb.append(" => 0x").append(Long.toHexString(value & 0xffffffffL));
                if (value < 0) {
                    sb.append(" (-0x").append(Integer.toHexString(-value)).append(")");
                }
            }
        } catch (UnicornException exception) {
            sb.append(" => ").append(exception.getMessage());
        }
    }

    private static final Log log = LogFactory.getLog(ARM.class);

    static Arguments initArgs(Emulator<?> emulator, boolean padding, Number... arguments) {
        Unicorn unicorn = emulator.getUnicorn();
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
            unicorn.reg_write(regArgs[i], list.remove(0));
            i++;
        }
        Collections.reverse(list);
        if (list.size() % 2 != 0) { // alignment sp
            memory.allocateStack(emulator.getPointerSize());
        }
        while (!list.isEmpty()) {
            Number number = list.remove(0);
            UnicornPointer pointer = memory.allocateStack(emulator.getPointerSize());
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

}
