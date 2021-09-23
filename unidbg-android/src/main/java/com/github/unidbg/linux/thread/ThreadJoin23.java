package com.github.unidbg.linux.thread;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Svc;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.ArmSvc;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.context.RegisterContext;
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
import java.util.concurrent.atomic.AtomicLong;

public class ThreadJoin23 {

    private static final Log log = LogFactory.getLog(ThreadJoin23.class);

    public static void patch(final Emulator<?> emulator, IHookZz hookZz, final ThreadJoinVisitor visitor) {
        Memory memory = emulator.getMemory();
        SvcMemory svcMemory = emulator.getSvcMemory();
        Module libc = memory.findModule("libc.so");
        Symbol clone = libc.findSymbolByName("clone", false);
        Symbol pthread_join = libc.findSymbolByName("pthread_join", false);
        if (clone == null || pthread_join == null) {
            throw new IllegalStateException("clone=" + clone + ", pthread_join=" + pthread_join);
        }
        final AtomicLong value_ptr = new AtomicLong();
        hookZz.replace(pthread_join, new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                Pointer ptr = context.getPointerArg(1);
                if (ptr != null) {
                    ptr.setInt(0, (int) value_ptr.get());
                }
                return HookStatus.LR(emulator, 0);
            }
        });
        hookZz.replace(clone, svcMemory.registerSvc(emulator.is32Bit() ? new ArmSvc() {
            private int threadId;
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                Pointer pthread_start = context.getPointerArg(0);
                Pointer child_stack = context.getPointerArg(1);
                int flags = context.getIntArg(2);
                Pointer thread = context.getPointerArg(3);

                Pointer start_routine = thread.getPointer(0x30);
                Pointer arg = thread.getPointer(0x34);
                log.info("clone start_routine=" + start_routine + ", child_stack=" + child_stack + ", flags=0x" + Integer.toHexString(flags) + ", arg=" + arg + ", pthread_start=" + pthread_start);

                Backend backend = emulator.getBackend();
                boolean join = visitor == null || visitor.canJoin(start_routine, ++threadId);
                UnidbgPointer pointer = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_SP);
                try {
                    pointer = pointer.share(-4, 0); // threadId
                    pointer.setInt(0, threadId);

                    if (join) {
                        pointer = pointer.share(-4, 0);
                        pointer.setPointer(0, start_routine);

                        pointer = pointer.share(-4, 0);
                        pointer.setPointer(0, arg);
                    }

                    pointer = pointer.share(-4, 0); // can join
                    pointer.setInt(0, join ? 1 : 0);
                } finally {
                    backend.reg_write(ArmConst.UC_ARM_REG_SP, pointer.peer);
                }
                return 0;
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
                            "pop {r0, ip}",
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
        } : new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        }));
    }

}
