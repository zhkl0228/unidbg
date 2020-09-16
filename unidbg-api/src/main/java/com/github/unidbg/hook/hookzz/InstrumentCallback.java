package com.github.unidbg.hook.hookzz;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.context.RegisterContext;

public abstract class InstrumentCallback<T extends RegisterContext> {

    public abstract void dbiCall(Emulator<?> emulator, T ctx, HookEntryInfo info);

}
