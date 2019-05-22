package cn.banny.unidbg.hook.hookzz;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.arm.RegisterContext;

public abstract class WrapCallback<T extends RegisterContext> {

    public abstract void preCall(Emulator emulator, T ctx, HookEntryInfo info);

    public void postCall(Emulator emulator, T ctx, HookEntryInfo info) {}

}
