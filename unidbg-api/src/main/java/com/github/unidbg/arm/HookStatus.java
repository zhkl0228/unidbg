package com.github.unidbg.arm;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.context.RegisterContext;

public class HookStatus {

    final long returnValue;
    final long jump;
    final boolean forward;

    private HookStatus(long returnValue, long jump, boolean forward) {
        this.returnValue = returnValue;
        this.jump = jump;
        this.forward = forward;
    }

    public static HookStatus RET(Emulator<?> emulator, long pc) {
        RegisterContext context = emulator.getContext();
        return new HookStatus(context.getLongArg(0), pc, true);
    }

    public static HookStatus LR(Emulator<?> emulator, long returnValue) {
        RegisterContext context = emulator.getContext();
        return new HookStatus(returnValue, context.getLR(), false);
    }

}
