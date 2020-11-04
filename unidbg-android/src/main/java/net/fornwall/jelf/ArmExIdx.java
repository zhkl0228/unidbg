package net.fornwall.jelf;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.unwind.Frame;
import com.github.unidbg.unwind.Unwinder;
import com.github.unidbg.utils.Inspector;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.ArmConst;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ArmExIdx {

    private static final Log log = LogFactory.getLog(ArmExIdx.class);

    private static final int ARM_EXIDX_CANT_UNWIND = 0x00000001;
    private static final int ARM_EXIDX_COMPACT = 0x80000000;
    private static final int ARM_EXTBL_OP_FINISH = 0xb0;

    private static final int ARM_EXIDX_VFP_SHIFT_16 = 1 << 16;
    private static final int ARM_EXIDX_VFP_DOUBLE = 1 << 17;

    private static final int UNW_ARM_SP = 13;
    private static final int UNW_ARM_LR = 14;
    private static final int UNW_ARM_PC = 15;

    enum arm_exbuf_cmd {
        ARM_EXIDX_CMD_FINISH,
        ARM_EXIDX_CMD_DATA_PUSH,
        ARM_EXIDX_CMD_DATA_POP,
        ARM_EXIDX_CMD_REG_POP,
        ARM_EXIDX_CMD_REG_TO_SP,
        ARM_EXIDX_CMD_VFP_POP,
        ARM_EXIDX_CMD_WREG_POP,
        ARM_EXIDX_CMD_WCGR_POP,
        ARM_EXIDX_CMD_RESERVED,
        ARM_EXIDX_CMD_REFUSED,
    }

    private final long virtualAddress;
    private final ByteBuffer buffer;

    ArmExIdx(long virtualAddress, ByteBuffer buffer) {
        this.virtualAddress = virtualAddress;
        this.buffer = buffer;
        this.buffer.order(ByteOrder.LITTLE_ENDIAN);
    }

    public Frame arm_exidx_step(Emulator<?> emulator, Unwinder unwinder, Module module, long fun, DwarfCursor context) {
        int value = ARM_EXIDX_CANT_UNWIND;

        buffer.position(0);
        long offset = virtualAddress;
        int entry = 0;
        while (buffer.hasRemaining()) {
            int key = buffer.getInt() << 1 >> 1;
            key += offset;

            if (fun >= key) {
                offset += 8;
                entry = key;
                value = buffer.getInt();
            } else {
                break;
            }
        }

        if (value == ARM_EXIDX_CANT_UNWIND) {
            return null;
        }

        if (fun == entry) { // first instruction of function
            UnidbgPointer ip = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_LR);
            UnidbgPointer fp = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_SP);
            Frame frame = unwinder.createFrame(ip, fp);
            if (frame != null) {
                context.ip = frame.ip.peer;
            }
            return frame;
        }

        byte[] instruction;
        boolean compact = (value & ARM_EXIDX_COMPACT) != 0;
        int index;
        ByteBuffer bb;
        if (compact) { // android_external_libunwind/src/arm/Gex_tables.c
            index = (value >> 24) & 0xf;
            if (index != 0) {
                throw new IllegalStateException("compact model must be Su16 / __aeabi_unwind_cpp_pr0");
            }
            bb = ByteBuffer.allocate(4);
            bb.putInt(value);
            instruction = Arrays.copyOfRange(bb.array(), 1, 4);
        } else {
            long addr = value + offset - 4;
            UnidbgPointer pointer = UnidbgPointer.pointer(emulator, module.base + addr);
            assert pointer != null;
            value = pointer.getInt(0);
            if ((value & ARM_EXIDX_COMPACT) == 0) {
                long personality = (value << 1 >> 1) + addr;
                int data = pointer.getInt(4);
                int n = (data >> 24) & 0xff;
                bb = ByteBuffer.allocate((n + 1) * 4);
                bb.putInt(data);
                for (int i = 0; i < n; i++) {
                    bb.putInt(pointer.getInt((i + 2) * 4));
                }
                instruction = Arrays.copyOfRange(bb.array(), 1, bb.capacity());
                if (log.isDebugEnabled()) {
                    log.debug("unwind generic model: " + module + ", entry=0x" + Integer.toHexString(entry) + ", personality=0x" + Long.toHexString(personality));
                }
            } else {
                index = (value >> 24) & 0xf;
                switch (index) {
                    case 0: // Su16 / __aeabi_unwind_cpp_pr0
                        bb = ByteBuffer.allocate(4);
                        bb.putInt(value);
                        instruction = Arrays.copyOfRange(bb.array(), 1, bb.capacity());
                        break;
                    case 1: // Lu16 / __aeabi_unwind_cpp_pr1
                    case 2: // Lu32 / __aeabi_unwind_cpp_pr1
                        int n = (value >> 16) & 0xff;
                        bb = ByteBuffer.allocate((n + 1) * 4);
                        bb.putInt(value);
                        for (int i = 0; i < n; i++) {
                            bb.putInt(pointer.getInt((i + 1) * 4));
                        }
                        instruction = Arrays.copyOfRange(bb.array(), 2, bb.capacity());
                        break;
                    default:
                        throw new UnsupportedOperationException("index=" + index);
                }
            }
        }
        if (instruction.length > 0 && (instruction[instruction.length - 1] & 0xff) != ARM_EXTBL_OP_FINISH) {
            byte[] tmp = new byte[instruction.length + 1];
            System.arraycopy(instruction, 0, tmp, 0, instruction.length);
            tmp[instruction.length] = (byte) ARM_EXTBL_OP_FINISH;
            instruction = tmp;
        }
        if (log.isDebugEnabled()) {
            log.debug(Inspector.inspectString(instruction, "unwind entry=0x" + Integer.toHexString(entry) + ", value=0x" + Integer.toHexString(value) + ", fun=0x" + Long.toHexString(fun) + ", module=" + module.name));
        }

        return arm_exidx_decode(emulator, instruction, unwinder, context);
    }

    private static class arm_exbuf_data {
        arm_exbuf_cmd cmd;
        int data;
    }

    private Frame arm_exidx_decode(Emulator<?> emulator, byte[] instruction, Unwinder unwinder, DwarfCursor context) {
        context.loc[UNW_ARM_PC] = null;

        arm_exbuf_data edata = new arm_exbuf_data();
        for (int i = 0; i < instruction.length; i++) {
            int op = instruction[i] & 0xff;
            if ((op & 0xc0) == 0x00) {
                edata.cmd = arm_exbuf_cmd.ARM_EXIDX_CMD_DATA_POP;
                edata.data = ((op & 0x3f) << 2) + 4;
            } else if ((op & 0xc0) == 0x40) {
                edata.cmd = arm_exbuf_cmd.ARM_EXIDX_CMD_DATA_PUSH;
                edata.data = ((op & 0x3f) << 2) + 4;
            } else if ((op & 0xf0) == 0x80) {
                int op2 = instruction[++i] & 0xff;
                if (op == 0x80 && op2 == 0x0) {
                    edata.cmd = arm_exbuf_cmd.ARM_EXIDX_CMD_REFUSED;
                } else {
                    edata.cmd = arm_exbuf_cmd.ARM_EXIDX_CMD_REG_POP;
                    edata.data = ((op & 0xf) << 8) | op2;
                    edata.data = edata.data << 4;
                }
            } else if ((op & 0xf0) == 0x90) {
                if (op == 0x9d || op == 0x9f) {
                    edata.cmd = arm_exbuf_cmd.ARM_EXIDX_CMD_RESERVED;
                } else {
                    edata.cmd = arm_exbuf_cmd.ARM_EXIDX_CMD_REG_TO_SP;
                    edata.data = op & 0xf;
                }
            } else if ((op & 0xf0) == 0xa0) {
                int end = op & 0x7;
                edata.data = (1 << (end + 1)) - 1;
                edata.data = edata.data << 4;
                if ((op & 0x8) != 0)
                    edata.data |= 1 << 14;
                edata.cmd = arm_exbuf_cmd.ARM_EXIDX_CMD_REG_POP;
            } else if (op == ARM_EXTBL_OP_FINISH) {
                edata.cmd = arm_exbuf_cmd.ARM_EXIDX_CMD_FINISH;
            } else if (op == 0xb1) {
                int op2 = instruction[++i] & 0xff;
                if (op2 == 0 || (op2 & 0xf0) != 0) {
                    edata.cmd = arm_exbuf_cmd.ARM_EXIDX_CMD_RESERVED;
                } else {
                    edata.cmd = arm_exbuf_cmd.ARM_EXIDX_CMD_REG_POP;
                    edata.data = op2 & 0xf;
                }
            } else if (op == 0xb2) {
                int offset = 0;
                byte b, shift = 0;
                do {
                    b = instruction[++i];
                    offset |= (b & 0x7f) << shift;
                    shift += 7;
                } while ((b & 0x80) != 0);
                edata.data = offset * 4 + 0x204;
                edata.cmd = arm_exbuf_cmd.ARM_EXIDX_CMD_DATA_POP;
            } else if (op == 0xb3 || op == 0xc8 || op == 0xc9) {
                edata.cmd = arm_exbuf_cmd.ARM_EXIDX_CMD_VFP_POP;
                edata.data = instruction[++i] & 0xff;
                if (op == 0xc8) {
                    edata.data |= ARM_EXIDX_VFP_SHIFT_16;
                }
                if (op != 0xb3) {
                    edata.data |= ARM_EXIDX_VFP_DOUBLE;
                }
            } else if ((op & 0xf8) == 0xb8 || (op & 0xf8) == 0xd0) {
                edata.cmd = arm_exbuf_cmd.ARM_EXIDX_CMD_VFP_POP;
                edata.data = 0x80 | (op & 0x7);
                if ((op & 0xf8) == 0xd0) {
                    edata.data |= ARM_EXIDX_VFP_DOUBLE;
                }
            } else if (op >= 0xc0 && op <= 0xc5) {
                edata.cmd = arm_exbuf_cmd.ARM_EXIDX_CMD_WREG_POP;
                edata.data = 0xa0 | (op & 0x7);
            } else if (op == 0xc6) {
                edata.cmd = arm_exbuf_cmd.ARM_EXIDX_CMD_WREG_POP;
                edata.data = instruction[++i] & 0xff;
            } else if (op == 0xc7) {
                int op2 = instruction[++i] & 0xff;
                if (op2 == 0 || (op2 & 0xf0) != 0) {
                    edata.cmd = arm_exbuf_cmd.ARM_EXIDX_CMD_RESERVED;
                } else {
                    edata.cmd = arm_exbuf_cmd.ARM_EXIDX_CMD_WCGR_POP;
                    edata.data = op2 & 0xf;
                }
            } else {
                edata.cmd = arm_exbuf_cmd.ARM_EXIDX_CMD_RESERVED;
            }

            if (!arm_exidx_apply_cmd(emulator, edata, context)) {
                return null;
            }
        }

        Long pc = context.loc[UNW_ARM_PC];
        if (pc != null) {
            return unwinder.createFrame(UnidbgPointer.pointer(emulator, pc), UnidbgPointer.pointer(emulator, context.cfa));
        }

        return null;
    }

    private boolean arm_exidx_apply_cmd(Emulator<?> emulator, arm_exbuf_data edata, DwarfCursor context) {
        switch (edata.cmd) {
            case ARM_EXIDX_CMD_FINISH: {
                /* Set LR to PC if not set already.  */
                if (context.loc[UNW_ARM_PC] == null) {
                    context.loc[UNW_ARM_PC] = context.loc[UNW_ARM_LR];
                }
                context.ip = context.loc[UNW_ARM_PC];
                if (log.isDebugEnabled()) {
                    log.debug("finish");
                }
                break;
            }
            case ARM_EXIDX_CMD_DATA_PUSH: {
                context.cfa -= edata.data;
                if (log.isDebugEnabled()) {
                    log.debug("vsp = vsp - " + edata.data);
                }
                break;
            }
            case ARM_EXIDX_CMD_DATA_POP: {
                context.cfa += edata.data;
                if (log.isDebugEnabled()) {
                    log.debug("vsp = vsp + " + edata.data);
                }
                break;
            }
            case ARM_EXIDX_CMD_REG_POP: {
                final List<String> list;
                if (log.isDebugEnabled()) {
                    list = null;
                } else {
                    list = new ArrayList<>(16);
                }
                for (int m = 0; m < 16; m++) {
                    if ((edata.data & (1 << m)) != 0) {
                        String reg = "r" + m;
                        if (list != null) {
                            list.add(reg);
                        }

                        UnidbgPointer sp = UnidbgPointer.pointer(emulator, context.cfa);
                        assert sp != null;
                        long value = sp.getInt(0) & 0xffffffffL;
                        context.loc[m] = value;
                        context.cfa += 4;
                        if (log.isDebugEnabled()) {
                            log.debug("pop " + reg + " -> 0x" + Long.toHexString(value));
                        }
                    }
                }
                /* Set cfa in case the SP got popped. */
                if ((edata.data & (1 << UNW_ARM_SP)) != 0) {
                    context.cfa = context.loc[UNW_ARM_SP];
                }
                if (log.isDebugEnabled() && list != null) {
                    log.debug("pop " + list.toString().replace('[', '{').replace(']', '}'));
                }
                break;
            }
            case ARM_EXIDX_CMD_REG_TO_SP: {
                long value = context.loc[edata.data];
                context.loc[UNW_ARM_SP] = value;
                if (log.isDebugEnabled()) {
                    log.debug("vsp = r" + edata.data + " [0x" + Long.toHexString(context.loc[UNW_ARM_SP]) + "]");
                }
                long sp = context.cfa;
                context.cfa = value;
                if (context.cfa == 0) {
                    System.err.println("vsp is null: sp=0x" + Long.toHexString(sp));
                    return false;
                }
                break;
            }
            case ARM_EXIDX_CMD_VFP_POP: {
                int start = (((edata.data) >> 4) & 0xf);
                int count = ((edata.data) & 0xf);
                int end = start + count;
                for (int m = start; m <= end; m++) {
                    context.cfa += 8;
                }
                if ((edata.data & ARM_EXIDX_VFP_DOUBLE) == 0) {
                    context.cfa += 4;
                }
                if (log.isDebugEnabled()) {
                    log.debug("pop {D" + start + "-D" + end + "}");
                }
                break;
            }
            case ARM_EXIDX_CMD_WREG_POP: {
                int start = (((edata.data) >> 4) & 0xf);
                int count = ((edata.data) & 0xf);
                int end = start + count;
                for (int m = start; m <= end; m++) {
                    context.cfa += 8;
                }
                break;
            }
            case ARM_EXIDX_CMD_WCGR_POP: {
                for (int m = 0; m < 4; m++) {
                    if ((edata.data & (1 << m)) != 0) {
                        context.cfa += 4;
                    }
                }
                break;
            }
            case ARM_EXIDX_CMD_REFUSED:
            case ARM_EXIDX_CMD_RESERVED:
                if (log.isDebugEnabled()) {
                    log.debug("cmd=" + edata.cmd);
                }
                return false;
            default:
                log.warn("arm_exidx_decode cmd=" + edata.cmd);
                return false;
        }
        return true;
    }

}
