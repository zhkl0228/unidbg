package com.github.unidbg;

import capstone.Arm64_const;
import capstone.Arm_const;
import unicorn.Arm64Const;
import capstone.api.Instruction;
import capstone.api.RegsAccess;
import com.alibaba.fastjson.util.IOUtils;
import com.github.unidbg.arm.InstructionVisitor;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.listener.TraceCodeListener;
import com.github.unidbg.memory.Memory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.PrintStream;
import java.util.Arrays;
import java.util.regex.Pattern;

/**
 * my code hook
 * Created by zhkl0228 on 2017/5/2.
 */

public class AssemblyCodeDumper implements CodeHook, TraceHook {

    private static final Logger log = LoggerFactory.getLogger(AssemblyCodeDumper.class);

    private static final Pattern LOAD_PATTERN = Pattern.compile("^(ldr|ldrb|ldrh|ldrsb|ldrsh|ldur|ldurb|ldurh|ldp|ldm)($|\\.|\\s).*");
    private static final Pattern STORE_PATTERN = Pattern.compile("^(str|strb|strh|stur|sturb|sturh|stp|stm)($|\\.|\\s).*");

    private final Emulator<?> emulator;

    public AssemblyCodeDumper(Emulator<?> emulator, long begin, long end, TraceCodeListener listener) {
        super();

        this.emulator = emulator;
        this.traceBegin = begin;
        this.traceEnd = end;
        this.listener = listener;

        Memory memory = emulator.getMemory();
        if (begin > end) {
            maxLengthLibraryName = memory.getMaxLengthLibraryName().length();
        } else {
            int value = 0;
            for (Module module : memory.getLoadedModules()) {
                long min = Math.max(begin, module.base);
                long max = Math.min(end, module.base + module.size);
                if (min < max) {
                    int length = module.name.length();
                    if (length > value) {
                        value = length;
                    }
                }
            }
            maxLengthLibraryName = value;
        }
    }

    private final long traceBegin, traceEnd;
    private final TraceCodeListener listener;
    private final int maxLengthLibraryName;

    private UnHook unHook;

    @Override
    public void onAttach(UnHook unHook) {
        if (this.unHook != null) {
            throw new IllegalStateException();
        }
        this.unHook = unHook;
    }

    @Override
    public void detach() {
        if (unHook != null) {
            unHook.unhook();
            unHook = null;
        }
    }

    @Override
    public void stopTrace() {
        detach();
        IOUtils.close(redirect);
        redirect = null;
    }

    private boolean canTrace(long address) {
        return (traceBegin > traceEnd || (address >= traceBegin && address <= traceEnd));
    }

    private PrintStream redirect;

    @Override
    public void setRedirect(PrintStream redirect) {
        this.redirect = redirect;
    }

    private RegAccessPrinter lastInstructionWritePrinter;

    @Override
    public void hook(final Backend backend, final long address, final int size, Object user) {
        if (canTrace(address)) {
            try {
                PrintStream out = System.err;
                if (redirect != null) {
                    out = redirect;
                }
                Instruction[] insns = emulator.printAssemble(out, address, size, maxLengthLibraryName, new InstructionVisitor() {
                    @Override
                    public void visitLast(StringBuilder builder) {
                        if (lastInstructionWritePrinter != null) {
                            lastInstructionWritePrinter.print(emulator, backend, builder, address);
                        }
                    }
                    @Override
                    public void visit(StringBuilder builder, Instruction ins) {
                        hookMemoryAccess(backend, ins, builder);

                        RegsAccess regsAccess = ins.regsAccess();
                        if (regsAccess != null) {
                            short[] regsRead = regsAccess.getRegsRead();
                            RegAccessPrinter readPrinter = new RegAccessPrinter(address, ins, regsRead, false);
                            readPrinter.print(emulator, backend, builder, address);

                            short[] regWrite = regsAccess.getRegsWrite();
                            if (regWrite.length > 0) {
                                lastInstructionWritePrinter = new RegAccessPrinter(address + size, ins, regWrite, true);
                            }
                        }
                    }
                });
                if (listener != null) {
                    if (insns == null || insns.length != 1) {
                        throw new IllegalStateException("insns=" + Arrays.toString(insns));
                    }
                    listener.onInstruction(emulator, address, insns[0]);
                }
            } catch (BackendException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    private void hookMemoryAccess(Backend backend, Instruction ins, StringBuilder builder) {
        try {
            String mnemonic = ins.getMnemonic();
            if (mnemonic == null) {
                return;
            }
            mnemonic = mnemonic.toLowerCase();

            boolean isLoad;
            if (LOAD_PATTERN.matcher(mnemonic).matches()) {
                isLoad = true;
            } else if (STORE_PATTERN.matcher(mnemonic).matches()) {
                isLoad = false;
            } else {
                return;
            }

            String tag = isLoad ? "r" : "w";
            if (emulator.is32Bit()) {
                capstone.api.arm.OpInfo opInfo = (capstone.api.arm.OpInfo) ins.getOperands();
                capstone.api.arm.Operand memOperand = null;
                for (capstone.api.arm.Operand op : opInfo.getOperands()) {
                    if (op.getType() == Arm_const.ARM_OP_MEM) {
                        memOperand = op;
                        break;
                    }
                }
                if (memOperand == null) {
                    return;
                }
                capstone.api.arm.MemType mem = memOperand.getValue().getMem();
                long baseValue = mem.getBase() != 0 ? backend.reg_read(ins.mapToUnicornReg(mem.getBase())).longValue() : 0;
                long indexValue = mem.getIndex() != 0 ? backend.reg_read(ins.mapToUnicornReg(mem.getIndex())).longValue() : 0;
                int lshift = mem.getLshift();
                long shiftedIndex = lshift != 0 ? indexValue << lshift : indexValue;
                if (memOperand.isSubtracted()) {
                    shiftedIndex = -shiftedIndex;
                }
                long absAddr = baseValue + shiftedIndex + mem.getDisp();
                int size = getArm32AccessSize(mnemonic, opInfo);
                builder.append(String.format(" (%s 0x%x %d)", tag, absAddr, size));
            } else {
                capstone.api.arm64.OpInfo opInfo = (capstone.api.arm64.OpInfo) ins.getOperands();
                capstone.api.arm64.Operand memOperand = null;
                for (capstone.api.arm64.Operand op : opInfo.getOperands()) {
                    if (op.getType() == Arm64_const.ARM64_OP_MEM) {
                        memOperand = op;
                        break;
                    }
                }
                if (memOperand == null) {
                    return;
                }
                capstone.api.arm64.MemType mem = memOperand.getValue().getMem();
                long baseValue = mem.getBase() != 0 ? readArm64Reg(backend, ins.mapToUnicornReg(mem.getBase())).longValue() : 0;
                long indexValue = mem.getIndex() != 0 ? readArm64Reg(backend, ins.mapToUnicornReg(mem.getIndex())).longValue() : 0;
                long shiftedIndex = indexValue;
                capstone.api.OpShift shift = memOperand.getShift();
                if (shift != null && shift.getValue() != 0) {
                    shiftedIndex = indexValue << shift.getValue();
                }
                long absAddr = baseValue + shiftedIndex + mem.getDisp();
                int elemSize = getArm64ElemSize(ins, mnemonic, opInfo);
                builder.append(String.format(" (%s 0x%x %d)", tag, absAddr, elemSize));
                if (mnemonic.startsWith("ldp") || mnemonic.startsWith("stp")) {
                    builder.append(String.format(" (%s 0x%x %d)", tag, absAddr + elemSize, elemSize));
                }
            }
        } catch (Exception e) {
            builder.append(" ; [mem_abs calc error: ").append(e.getMessage()).append("]");
            log.warn("hookMemoryAccess failed", e);
        }
    }

    private int getArm32AccessSize(String mnemonic, capstone.api.arm.OpInfo opInfo) {
        if (mnemonic.startsWith("ldrb") || mnemonic.startsWith("strb") || mnemonic.startsWith("ldrsb")) {
            return 1;
        }
        if (mnemonic.startsWith("ldrh") || mnemonic.startsWith("strh") || mnemonic.startsWith("ldrsh")) {
            return 2;
        }
        if (mnemonic.startsWith("ldm") || mnemonic.startsWith("stm")) {
            int regCount = 0;
            for (capstone.api.arm.Operand op : opInfo.getOperands()) {
                if (op.getType() == Arm_const.ARM_OP_REG) {
                    regCount++;
                }
            }
            return 4 * Math.max(regCount, 1);
        }
        return 4;
    }

    private int getArm64ElemSize(Instruction ins, String mnemonic, capstone.api.arm64.OpInfo opInfo) {
        if (mnemonic.endsWith("b")) return 1;  // ldrb, strb, ldurb, sturb, ldrsb
        if (mnemonic.endsWith("h")) return 2;  // ldrh, strh, ldurh, sturh, ldrsh
        if (mnemonic.endsWith("w")) return 4;  // ldrsw, ldpsw
        // Infer size from first register operand (map to unicorn regId for range checks)
        for (capstone.api.arm64.Operand op : opInfo.getOperands()) {
            if (op.getType() == Arm64_const.ARM64_OP_REG) {
                return arm64RegSize(ins.mapToUnicornReg(op.getValue().getReg()));
            }
        }
        return 8;
    }

    private Number readArm64Reg(Backend backend, int regId) throws BackendException {
        // XZR/WZR always read as zero
        if (regId == Arm64Const.UC_ARM64_REG_XZR || regId == Arm64Const.UC_ARM64_REG_WZR) return 0L;
        // WSP is the 32-bit view of SP; map to SP
        if (regId == Arm64Const.UC_ARM64_REG_WSP) return backend.reg_read(Arm64Const.UC_ARM64_REG_SP);
        return backend.reg_read(regId);
    }

    private int arm64RegSize(int regId) {
        if (regId >= Arm64Const.UC_ARM64_REG_B0 && regId <= Arm64Const.UC_ARM64_REG_B31) return 1;
        if (regId >= Arm64Const.UC_ARM64_REG_D0 && regId <= Arm64Const.UC_ARM64_REG_D31) return 8;
        if (regId >= Arm64Const.UC_ARM64_REG_H0 && regId <= Arm64Const.UC_ARM64_REG_H31) return 2;
        if (regId >= Arm64Const.UC_ARM64_REG_Q0 && regId <= Arm64Const.UC_ARM64_REG_Q31) return 16;
        if (regId >= Arm64Const.UC_ARM64_REG_S0 && regId <= Arm64Const.UC_ARM64_REG_S31) return 4;
        if ((regId >= Arm64Const.UC_ARM64_REG_W0 && regId <= Arm64Const.UC_ARM64_REG_W30) || regId == Arm64Const.UC_ARM64_REG_WZR) return 4;
        return 8; // X0-X28, X29, X30, SP, XZR
    }

}
