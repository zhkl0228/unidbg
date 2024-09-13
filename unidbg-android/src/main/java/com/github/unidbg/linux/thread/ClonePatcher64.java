package com.github.unidbg.linux.thread;

import com.github.unidbg.Emulator;
import com.github.unidbg.Svc;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.context.RegisterContext;
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

class ClonePatcher64 extends Arm64Svc {

    private static final Logger log = LoggerFactory.getLogger(ClonePatcher64.class);

    private final ThreadJoinVisitor visitor;
    private final AtomicLong value_ptr;
    private int threadId;

    public ClonePatcher64(ThreadJoinVisitor visitor, AtomicLong value_ptr) {
        this.visitor = visitor;
        this.value_ptr = value_ptr;
    }

    @Override
    public long handle(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer pthread_start = context.getPointerArg(0);
        Pointer child_stack = context.getPointerArg(1);
        int flags = context.getIntArg(2);
        Pointer thread = context.getPointerArg(3);

        Pointer start_routine = thread.getPointer(0x60);
        Pointer arg = thread.getPointer(0x68);
        log.info("clone start_routine={}, child_stack={}, flags=0x{}, arg={}, pthread_start={}", start_routine, child_stack, Integer.toHexString(flags), arg, pthread_start);

        Backend backend = emulator.getBackend();
        boolean join = visitor == null || visitor.canJoin(start_routine, ++threadId);
        UnidbgPointer pointer = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_SP);
        try {
            pointer = pointer.share(-8, 0); // threadId
            pointer.setLong(0, threadId);

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
