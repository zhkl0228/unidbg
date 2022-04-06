package com.github.unidbg;

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

/**
 * my code hook
 * Created by zhkl0228 on 2017/5/2.
 */

public class AssemblyCodeDumper implements CodeHook, TraceHook {

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

}
