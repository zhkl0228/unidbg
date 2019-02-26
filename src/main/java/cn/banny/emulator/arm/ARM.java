package cn.banny.emulator.arm;

import capstone.Capstone;
import cn.banny.emulator.Emulator;
import cn.banny.emulator.memory.Memory;
import cn.banny.emulator.linux.Module;
import com.sun.jna.Pointer;
import unicorn.Arm64Const;
import unicorn.ArmConst;
import unicorn.Unicorn;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
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

    public static void showThumbRegs(Unicorn unicorn) {
        showRegs(unicorn, ARM.THUMB_REGS);
    }

    public static void showRegs(Unicorn unicorn, int[] regs) {
        if (regs == null || regs.length < 1) {
            regs = ARM.getAllRegisters(isThumb(unicorn));
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
                    builder.append(String.format(Locale.US, ", r3=0x%x", value));
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
                case ArmConst.UC_ARM_REG_R9:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.intValue();
                    builder.append(String.format(Locale.US, " r9=0x%x", value));
                    break;
                case ArmConst.UC_ARM_REG_R10:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.intValue();
                    builder.append(String.format(Locale.US, " r10=0x%x", value));
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
                    builder.append(String.format(Locale.US, " sp=0x%x", value));
                    break;
                case ArmConst.UC_ARM_REG_LR:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.intValue();
                    builder.append(String.format(Locale.US, " lr=0x%x", value));
                    break;
                case ArmConst.UC_ARM_REG_PC:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.intValue();
                    builder.append(String.format(Locale.US, " pc=0x%x", value));
                    break;
            }
        }
        System.out.println(builder.toString());
    }

    public static void showRegs64(Unicorn unicorn, int[] regs) {
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
                    builder.append(String.format(Locale.US, ", x3=0x%x", value));
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
                    builder.append(String.format(Locale.US, "\nsp=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_LR:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, "\nlr=0x%x", value));
                    break;
                case Arm64Const.UC_ARM64_REG_PC:
                    number = (Number) unicorn.reg_read(reg);
                    value = number.longValue();
                    builder.append(String.format(Locale.US, "\npc=0x%x", value));
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

    public static int[] getRegArgs(Emulator emulator) {
        return emulator.getPointerSize() == 4 ? ARM_ARG_REGS : ARM64_ARG_REGS;
    }

    private static int[] getAllRegisters(boolean thumb) {
        return thumb ? THUMB_REGS : ARM_REGS;
    }

    private static int[] getAll64Registers() {
        return ARM64_REGS;
    }

    private static final int ALIGN_SIZE_BASE = 4;

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

    private static final Pattern LDR_PATTERN = Pattern.compile("\\w+,\\s\\[pc,\\s#0x(\\w+)]");

    public static String assembleDetail(Memory memory, Capstone.CsInsn ins, long address, boolean thumb) {
        return assembleDetail(memory, ins, address, thumb, ' ');
    }

    static String assembleDetail(Memory memory, Capstone.CsInsn ins, long address, boolean thumb, char space) {
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

        if ("ldr".equals(ins.mnemonic)) {
            Matcher matcher = LDR_PATTERN.matcher(ins.opStr);
            if (matcher.find()) {
                long addr = ins.address + Long.parseLong(matcher.group(1), 16);
                addr += (thumb ? 4 : 8);
                Pointer pointer = memory.pointer(addr & 0xfffffffffffffffcL);
                int value = pointer.getInt(0);
                sb.append(" => 0x").append(Long.toHexString(value & 0xffffffffL));
                if (value < 0) {
                    sb.append(" (-0x").append(Integer.toHexString(-value)).append(")");
                }
            }
        }

        return sb.toString();
    }

}
