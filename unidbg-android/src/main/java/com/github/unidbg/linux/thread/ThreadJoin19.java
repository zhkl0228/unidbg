package com.github.unidbg.linux.thread;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Svc;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.ArmSvc;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.context.EditableArm32RegisterContext;
import com.github.unidbg.hook.HookContext;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.hookzz.IHookZz;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.ArmConst;

import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

public class ThreadJoin19 {

    private static final Log log = LogFactory.getLog(ThreadJoin19.class);

    public static void patch(final Emulator<?> emulator, IHookZz hookZz, final ThreadJoinVisitor visitor) {
        if (emulator.is64Bit()) {
            throw new IllegalStateException();
        }
        Memory memory = emulator.getMemory();
        SvcMemory svcMemory = emulator.getSvcMemory();
        Module libc = memory.findModule("libc.so");
        Symbol _pthread_clone = libc.findSymbolByName("__pthread_clone", false);
        Symbol pthread_join = libc.findSymbolByName("pthread_join", false);
        if (_pthread_clone == null || pthread_join == null) {
            throw new IllegalStateException("_pthread_clone=" + _pthread_clone + ", pthread_join=" + pthread_join);
        }
        final AtomicInteger value_ptr = new AtomicInteger();
        hookZz.replace(pthread_join, new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                Pointer ptr = context.getPointerArg(1);
                if (ptr != null) {
                    ptr.setInt(0, value_ptr.get());
                }
                return HookStatus.LR(emulator, 0);
            }
        });
        hookZz.replace(_pthread_clone, svcMemory.registerSvc(new ArmSvc() {
            private int threadId;
            @Override
            public long handle(Emulator<?> emulator) {
                EditableArm32RegisterContext context = emulator.getContext();
                Pointer start_routine = context.getPointerArg(0);
                Pointer child_stack = context.getPointerArg(1);
                int flags = context.getIntArg(2);
                Pointer arg = context.getPointerArg(3);
                log.info("pthread_clone start_routine=" + start_routine + ", child_stack=" + child_stack + ", flags=0x" + Integer.toHexString(flags) + ", arg=" + arg);

                Backend backend = emulator.getBackend();
                boolean join = visitor == null || visitor.canJoin(start_routine, ++threadId);
                UnidbgPointer pointer = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_SP);
                try {
                    pointer = pointer.share(-4, 0); // threadId
                    pointer.setInt(0, threadId);

                    pointer = pointer.share(-4, 0); // can join
                    pointer.setInt(0, join ? 1 : 0);
                } finally {
                    backend.reg_write(ArmConst.UC_ARM_REG_SP, pointer.peer);
                }
                return context.getR0Int();
            }
            @Override
            public UnidbgPointer onRegister(SvcMemory svcMemory, int svcNumber) {
                try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm, KeystoneMode.Arm)) {
                    KeystoneEncoded encoded = keystone.assemble(Arrays.asList(
                            "push {r4-r7, lr}",
                            "svc #0x" + Integer.toHexString(svcNumber),
                            "pop {r7}",
                            "cmp r7, #0",
                            "popeq {r0, r4-r7, pc}",
                            "mov ip, r0",
                            "mov r0, r3",
                            "blx ip",
                            "mov r7, #0",
                            "mov r5, #0x" + Integer.toHexString(Svc.CALLBACK_SYSCALL_NUMBER),
                            "mov r4, #0x" + Integer.toHexString(svcNumber),
                            "svc #0",
                            "pop {r0, r4-r7, pc}"));
                    byte[] code = encoded.getMachineCode();
                    UnidbgPointer pointer = svcMemory.allocate(code.length, ThreadJoin19.class.getSimpleName());
                    pointer.write(code);
                    return pointer;
                }
            }
            @Override
            public void handleCallback(Emulator<?> emulator) {
                super.handleCallback(emulator);
                value_ptr.set(emulator.getContext().getIntArg(0));
            }
        }));
    }

}
