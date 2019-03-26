package cn.banny.emulator.hook.hookzz;

import cn.banny.emulator.Emulator;

public abstract class WrapCallback<T extends RegisterContext> {

    public abstract void preCall(Emulator emulator, T ctx, HookEntryInfo info);

    public void postCall(Emulator emulator, T ctx, HookEntryInfo info) {}

}
