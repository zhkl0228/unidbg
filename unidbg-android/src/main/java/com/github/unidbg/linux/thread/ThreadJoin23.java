package com.github.unidbg.linux.thread;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.ArmSvc;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.hook.hookzz.IHookZz;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class ThreadJoin23 {

    public static void patch(Emulator<?> emulator, IHookZz hookZz) {
        Memory memory = emulator.getMemory();
        SvcMemory svcMemory = emulator.getSvcMemory();
        Module libc = memory.findModule("libc.so");
        Symbol clone = libc.findSymbolByName("clone", false);
        if (clone == null) {
            throw new IllegalStateException("find clone failed.");
        }
        hookZz.replace(clone, svcMemory.registerSvc(emulator.is32Bit() ? new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                Pointer pthread_start = context.getPointerArg(0);
                Pointer child_stack = context.getPointerArg(1);
                int flags = context.getIntArg(2);
                Pointer thread = context.getPointerArg(3);
                System.out.println("clone pthread_start=" + pthread_start + ", child_stack=" + child_stack + ", flags=0x" + Integer.toHexString(flags) + ", thread=" + thread);
                return 0;
            }
            @Override
            public UnidbgPointer onRegister(SvcMemory svcMemory, int svcNumber) {
                ByteBuffer buffer = ByteBuffer.allocate(8);
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                buffer.putInt(assembleSvc(svcNumber)); // svc #svcNumber
                buffer.putInt(0xe12fff1e); // bx lr
                byte[] code = buffer.array();
                UnidbgPointer pointer = svcMemory.allocate(code.length, "ArmSvc");
                pointer.write(code);
                return pointer;
            }
        } : new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        }));
    }

}
