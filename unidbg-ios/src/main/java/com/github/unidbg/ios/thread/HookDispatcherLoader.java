package com.github.unidbg.ios.thread;

import com.github.unidbg.Emulator;
import com.github.unidbg.hook.BaseHook;
import com.github.unidbg.ios.hook.Substrate;

public class HookDispatcherLoader extends BaseHook {

    public static HookDispatcherLoader load(Emulator<?> emulator) {
        Substrate.getInstance(emulator); // load substrate first

        HookDispatcherLoader loader = emulator.get(HookDispatcherLoader.class.getName());
        if (loader == null) {
            loader = new HookDispatcherLoader(emulator);
            emulator.set(HookDispatcherLoader.class.getName(), loader);
        }
        return loader;
    }

    private HookDispatcherLoader(Emulator<?> emulator) {
        super(emulator, "libhookdispatch");
    }

}
