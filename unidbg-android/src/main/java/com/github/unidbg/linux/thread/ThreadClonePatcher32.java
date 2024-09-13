package com.github.unidbg.linux.thread;

import com.github.unidbg.Emulator;
import com.github.unidbg.Svc;
import com.github.unidbg.arm.ArmSvc;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.context.EditableArm32RegisterContext;
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
import unicorn.ArmConst;

import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

class ThreadClonePatcher32 extends ArmSvc {

    private static final Logger log = LoggerFactory.getLogger(ThreadClonePatcher32.class);

    private final ThreadJoinVisitor visitor;
    private final AtomicInteger value_ptr;
    private int threadId;

    public ThreadClonePatcher32(ThreadJoinVisitor visitor, AtomicInteger value_ptr) {
        this.visitor = visitor;
        this.value_ptr = value_ptr;
    }

    @Override
    public long handle(Emulator<?> emulator) {
        EditableArm32RegisterContext context = emulator.getContext();
        Pointer start_routine = context.getPointerArg(0);
        Pointer child_stack = context.getPointerArg(1);
        int flags = context.getIntArg(2);
        Pointer arg = context.getPointerArg(3);
        log.info("pthread_clone start_routine={}, child_stack={}, flags=0x{}, arg={}", start_routine, child_stack, Integer.toHexString(flags), arg);

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

                    "mov r7, #0",
                    "mov r5, #0x" + Integer.toHexString(Svc.PRE_CALLBACK_SYSCALL_NUMBER),
                    "mov r4, #0x" + Integer.toHexString(svcNumber),
                    "svc #0",

                    "blx ip",

                    "mov r7, #0",
                    "mov r5, #0x" + Integer.toHexString(Svc.POST_CALLBACK_SYSCALL_NUMBER),
                    "mov r4, #0x" + Integer.toHexString(svcNumber),
                    "svc #0",

                    "pop {r0, r4-r7, pc}"));
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
        value_ptr.set(emulator.getContext().getIntArg(0));
    }
}
