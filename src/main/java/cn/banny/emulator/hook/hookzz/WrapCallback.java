package cn.banny.emulator.hook.hookzz;

import unicorn.Unicorn;

public abstract class WrapCallback<T extends RegisterContext> {

    public abstract void preCall(Unicorn u, T ctx, HookEntryInfo info);

    public void postCall(Unicorn u, T ctx, HookEntryInfo info) {}

}
