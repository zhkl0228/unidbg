package com.github.unidbg.ios.thread;

import com.github.unidbg.Emulator;
import com.github.unidbg.Svc;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.ios.DarwinSyscall;
import com.github.unidbg.ios.struct.kernel.Pthread;
import com.github.unidbg.ios.struct.kernel.Pthread64;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.unix.ThreadJoinVisitor;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import unicorn.Arm64Const;

import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;

class BsdThreadCreatePatcher64 extends Arm64Svc {

    private static final Logger log = LoggerFactory.getLogger(BsdThreadCreatePatcher64.class);

    private final ThreadJoinVisitor visitor;
    private final AtomicLong value_ptr;
    private int threadId;

    BsdThreadCreatePatcher64(ThreadJoinVisitor visitor, AtomicLong value_ptr) {
        this.visitor = visitor;
        this.value_ptr = value_ptr;
    }

    @Override
    public long handle(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer start_routine = context.getPointerArg(0);
        Pointer arg = context.getPointerArg(1);
        Pointer stack = context.getPointerArg(2);
        Pointer thread = context.getPointerArg(3);
        int flags = context.getIntArg(4);
        log.info("bsdthread_create start_routine={}, arg={}, stack={}, thread={}, flags=0x{}", start_routine, arg, stack, thread, Integer.toHexString(flags));

        if (thread == null) {
            MemoryBlock memoryBlock = emulator.getMemory().malloc(0x100, true);
            thread = memoryBlock.getPointer();
        }
        Pthread pThread = new Pthread64(thread);
        pThread.setSelf(thread);
        pThread.setMachThreadSelf(DarwinSyscall.STATIC_PORT);
        pThread.pack();

        Backend backend = emulator.getBackend();
        boolean join = visitor == null || visitor.canJoin(start_routine, ++threadId);
        UnidbgPointer pointer = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_SP);
        try {
            pointer = pointer.share(-8, 0);
            pointer.setPointer(0, thread);

            if (join) {
                pointer = pointer.share(-8, 0);
                pointer.setPointer(0, start_routine);

                pointer = pointer.share(-8, 0);
                pointer.setPointer(0, arg);
            }

            pointer = pointer.share(-8, 0); // can join
            pointer.setLong(0, join ? 1 : 0);
        } finally {
            backend.reg_write(Arm64Const.UC_ARM64_REG_SP, pointer.peer);
        }
        return 0;
    }

    @Override
    public UnidbgPointer onRegister(SvcMemory svcMemory, int svcNumber) {
        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian)) {
            KeystoneEncoded encoded = keystone.assemble(Arrays.asList(
                    "sub sp, sp, #0x10",
                    "stp x29, x30, [sp]",
                    "svc #0x" + Integer.toHexString(svcNumber),

                    "ldr x13, [sp]",
                    "add sp, sp, #0x8",
                    "cmp x13, #0",
                    "b.eq #0x48",

                    "ldp x0, x13, [sp]",
                    "add sp, sp, #0x10",

                    "mov x8, #0",
                    "mov x12, #0x" + Integer.toHexString(svcNumber),
                    "mov x16, #0x" + Integer.toHexString(Svc.PRE_CALLBACK_SYSCALL_NUMBER),
                    "svc #0",

                    "blr x13",

                    "mov x8, #0",
                    "mov x12, #0x" + Integer.toHexString(svcNumber),
                    "mov x16, #0x" + Integer.toHexString(Svc.POST_CALLBACK_SYSCALL_NUMBER),
                    "svc #0",

                    "ldr x0, [sp]",
                    "add sp, sp, #0x8",

                    "ldp x29, x30, [sp]",
                    "add sp, sp, #0x10",
                    "ret"));
            byte[] code = encoded.getMachineCode();
            UnidbgPointer pointer = svcMemory.allocate(code.length, getClass().getSimpleName());
            pointer.write(code);
            return pointer;
        }
    }

    @Override
    public void handlePreCallback(Emulator<?> emulator) {
        if (visitor.isSaveContext()) {
            emulator.pushContext(0x4);
        }
    }

    @Override
    public void handlePostCallback(Emulator<?> emulator) {
        super.handlePostCallback(emulator);
        value_ptr.set(emulator.getContext().getLongArg(0));
    }

}
