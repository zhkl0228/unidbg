package com.github.unidbg;

import capstone.Arm64_const;
import capstone.Arm_const;
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

import java.io.PrintStream;
import java.util.Arrays;
import java.util.regex.Pattern;

/**
 * my code hook
 * Created by zhkl0228 on 2017/5/2.
 */

public class AssemblyCodeDumper implements CodeHook, TraceHook {

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

            String accessType;
            if (LOAD_PATTERN.matcher(mnemonic).matches()) {
                accessType = "READ";
            } else if (STORE_PATTERN.matcher(mnemonic).matches()) {
                accessType = "WRITE";
            } else {
                return;
            }

            long absAddr;
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
                long baseValue = mem.getBase() != 0 ? backend.reg_read(mem.getBase()).longValue() : 0;
                long indexValue = mem.getIndex() != 0 ? backend.reg_read(mem.getIndex()).longValue() : 0;
                int lshift = mem.getLshift();
                long shiftedIndex = lshift != 0 ? indexValue << lshift : indexValue;
                if (memOperand.isSubtracted()) {
                    shiftedIndex = -shiftedIndex;
                }
                absAddr = baseValue + shiftedIndex + mem.getDisp();
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
                long baseValue = mem.getBase() != 0 ? backend.reg_read(mem.getBase()).longValue() : 0;
                long indexValue = mem.getIndex() != 0 ? backend.reg_read(mem.getIndex()).longValue() : 0;
                long shiftedIndex = indexValue;
                capstone.api.OpShift shift = memOperand.getShift();
                if (shift != null && shift.getValue() != 0) {
                    shiftedIndex = indexValue << shift.getValue();
                }
                absAddr = baseValue + shiftedIndex + mem.getDisp();
            }

            builder.append(String.format(" ; mem[%s] abs=0x%x", accessType, absAddr));
        } catch (Exception e) {
            builder.append(" ; [mem_abs calc error: ").append(e.getMessage()).append("]");
        }
    }

}
