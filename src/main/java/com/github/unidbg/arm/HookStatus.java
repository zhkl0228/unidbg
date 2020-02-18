package com.github.unidbg.arm;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.context.RegisterContext;

public class HookStatus {

    final long r0;
    final long r1;
    final long jump;
    final boolean forward;

    private HookStatus(long r0, long r1, long jump, boolean forward) {
        this.r0 = r0;
        this.r1 = r1;
        this.jump = jump;
        this.forward = forward;
    }

    public static HookStatus RET(Emulator emulator, long pc) {
        RegisterContext context = emulator.getContext();
        return new HookStatus(context.getLongArg(0), context.getLongArg(1), pc, true);
    }

    public static HookStatus LR(Emulator emulator, long returnValue) {
        RegisterContext context = emulator.getContext();
        return new HookStatus(returnValue, context.getLongArg(1), context.getLR(), false);
    }

    public static HookStatus LR(Emulator emulator, long r0, long r1) {
        RegisterContext context = emulator.getContext();
        return new HookStatus(r0, r1, context.getLR(), false);
    }

}
