package com.github.unidbg.arm;

public class NestedRun extends RuntimeException {

    public final long pc;

    private NestedRun(long pc) {
        super("NestedRun: 0x" + Long.toHexString(pc));
        this.pc = pc;
    }

    /**
     * need custom fix call context.
     */
    public static NestedRun runToFunction(long pc) {
        return new NestedRun(pc);
    }

}
