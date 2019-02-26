package cn.banny.emulator;

import unicorn.CodeHook;
import unicorn.Unicorn;

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

    @Override
    public void hook(Unicorn u, long address, int size, Object user) {
        if (canTrace(address)) {
            if (!emulator.printAssemble(address, size)) {
                System.err.println("### Trace Instruction at 0x" + Long.toHexString(address) + ", size = " + size);
            }
        }
    }

}
