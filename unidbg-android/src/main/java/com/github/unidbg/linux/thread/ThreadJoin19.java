package com.github.unidbg.linux.thread;

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

import java.util.concurrent.atomic.AtomicInteger;

public class ThreadJoin19 {

    public static void patch(final Emulator<?> emulator, InlineHook inlineHook, final ThreadJoinVisitor visitor) {
        if (emulator.is64Bit()) {
            throw new IllegalStateException();
        }
        Memory memory = emulator.getMemory();
        Module libc = memory.findModule("libc.so");
        Symbol _pthread_clone = libc.findSymbolByName("__pthread_clone", false);
        Symbol pthread_join = libc.findSymbolByName("pthread_join", false);
        if (_pthread_clone == null || pthread_join == null) {
            throw new IllegalStateException("_pthread_clone=" + _pthread_clone + ", pthread_join=" + pthread_join);
        }
        final AtomicInteger value_ptr = new AtomicInteger();
        inlineHook.replace(pthread_join, new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                Pointer ptr = context.getPointerArg(1);
                if (ptr != null) {
                    ptr.setInt(0, value_ptr.get());
                }
                return HookStatus.LR(emulator, 0);
            }
        });
        inlineHook.replace(_pthread_clone, new ThreadClonePatcher32(visitor, value_ptr));
    }

}
