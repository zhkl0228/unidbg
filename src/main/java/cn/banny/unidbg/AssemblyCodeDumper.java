package cn.banny.unidbg;

import unicorn.CodeHook;
import unicorn.Unicorn;

import java.io.PrintStream;

/**
 * my code hook
 * Created by zhkl0228 on 2017/5/2.
 */

class AssemblyCodeDumper implements CodeHook {

    private final Emulator emulator;

    AssemblyCodeDumper(Emulator emulator) {
        super();

        this.emulator = emulator;
    }

    private boolean traceInstruction;
    private long traceBegin, traceEnd;

    void initialize(long begin, long end) {
        this.traceInstruction = true;
        this.traceBegin = begin;
        this.traceEnd = end;
    }

    private boolean canTrace(long address) {
        return traceInstruction && (traceBegin > traceEnd || address >= traceBegin && address <= traceEnd);
    }

    PrintStream redirect;

    @Override
    public void hook(Unicorn u, long address, int size, Object user) {
        if (canTrace(address)) {
            if (!emulator.printAssemble(address, size)) {
                PrintStream out = System.err;
                if (redirect != null) {
                    out = redirect;
                }
                out.println("### Trace Instruction at 0x" + Long.toHexString(address) + ", size = " + size);
            }
        }
    }

}
