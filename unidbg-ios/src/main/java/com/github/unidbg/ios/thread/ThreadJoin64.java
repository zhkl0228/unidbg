package com.github.unidbg.ios.thread;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.hook.HookContext;
import com.github.unidbg.hook.InlineHook;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.unix.ThreadJoinVisitor;
import com.sun.jna.Pointer;

import java.util.concurrent.atomic.AtomicLong;

public class ThreadJoin64 {

    public static void patch(final Emulator<?> emulator, InlineHook inlineHook, final ThreadJoinVisitor visitor) {
        Memory memory = emulator.getMemory();
        Module kernel = memory.findModule("libsystem_kernel.dylib");
        Module pthread = memory.findModule("libsystem_pthread.dylib");
        Symbol thread_create = kernel.findSymbolByName("___bsdthread_create", false);
        Symbol pthread_join = pthread.findSymbolByName("_pthread_join", false);
        if (thread_create == null || pthread_join == null) {
            throw new IllegalStateException("thread_create=" + thread_create + ", pthread_join=" + pthread_join);
        }
        final AtomicLong value_ptr = new AtomicLong();
        inlineHook.replace(pthread_join, new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                Pointer ptr = context.getPointerArg(1);
                if (ptr != null) {
                    ptr.setLong(0, value_ptr.get());
                }
                return HookStatus.LR(emulator, 0);
            }
        });
        inlineHook.replace(thread_create, new BsdThreadCreatePatcher64(visitor, value_ptr));
    }

}
