package com.github.unidbg;

import capstone.Capstone;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.listener.TraceCodeListener;

import java.io.PrintStream;
import java.util.Arrays;

/**
 * my code hook
 * Created by zhkl0228 on 2017/5/2.
 */

public class AssemblyCodeDumper implements CodeHook {

    private final Emulator<?> emulator;

    public AssemblyCodeDumper(Emulator<?> emulator) {
        super();

        this.emulator = emulator;
    }

    private boolean traceInstruction;
    private long traceBegin, traceEnd;
    private TraceCodeListener listener;

    public void initialize(long begin, long end, TraceCodeListener listener) {
        this.traceInstruction = true;
        this.traceBegin = begin;
        this.traceEnd = end;
        this.listener = listener;
    }

    private boolean canTrace(long address) {
        return traceInstruction && (traceBegin > traceEnd || (address >= traceBegin && address <= traceEnd));
    }

    PrintStream redirect;

    public void setRedirect(PrintStream redirect) {
        this.redirect = redirect;
    }

    @Override
    public void hook(Backend backend, long address, int size, Object user) {
        if (canTrace(address)) {
            try {
                PrintStream out = System.out;
                if (redirect != null) {
                    out = redirect;
                }
                Capstone.CsInsn[] insns = emulator.printAssemble(out, address, size);
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
