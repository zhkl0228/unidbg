package com.github.unidbg;

import capstone.Capstone;
import com.github.unidbg.listener.TraceCodeListener;
import unicorn.CodeHook;
import unicorn.Unicorn;

import java.io.PrintStream;
import java.util.Arrays;

/**
 * my code hook
 * Created by zhkl0228 on 2017/5/2.
 */

class AssemblyCodeDumper implements CodeHook {

    private final Emulator<?> emulator;

    AssemblyCodeDumper(Emulator<?> emulator) {
        super();

        this.emulator = emulator;
    }

    private boolean traceInstruction;
    private long traceBegin, traceEnd;
    private TraceCodeListener listener;

    void initialize(long begin, long end, TraceCodeListener listener) {
        this.traceInstruction = true;
        this.traceBegin = begin;
        this.traceEnd = end;
        this.listener = listener;
    }

    private boolean canTrace(long address) {
        return traceInstruction && (traceBegin > traceEnd || (address >= traceBegin && address <= traceEnd));
    }

    PrintStream redirect;

    @Override
    public void hook(Unicorn u, long address, int size, Object user) {
        if (canTrace(address)) {
            PrintStream out = System.err;
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
        }
    }

}
