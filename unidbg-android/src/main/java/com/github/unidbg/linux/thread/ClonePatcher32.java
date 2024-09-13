package com.github.unidbg.linux.thread;

import com.github.unidbg.Emulator;
import com.github.unidbg.Svc;
import com.github.unidbg.arm.ArmSvc;
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
import unicorn.ArmConst;

import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;

class ClonePatcher32 extends ArmSvc {

    private static final Logger log = LoggerFactory.getLogger(ClonePatcher32.class);

    private final ThreadJoinVisitor visitor;
    private final AtomicLong value_ptr;
    private int threadId;

    public ClonePatcher32(ThreadJoinVisitor visitor, AtomicLong value_ptr) {
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

        Pointer start_routine = thread.getPointer(0x30);
        Pointer arg = thread.getPointer(0x34);
        log.info("clone start_routine={}, child_stack={}, flags=0x{}, arg={}, pthread_start={}", start_routine, child_stack, Integer.toHexString(flags), arg, pthread_start);

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
