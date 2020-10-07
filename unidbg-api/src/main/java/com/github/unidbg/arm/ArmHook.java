package com.github.unidbg.arm;

import com.github.unidbg.Emulator;
import com.github.unidbg.Svc;
import com.github.unidbg.arm.backend.Backend;
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

public abstract class ArmHook extends ArmSvc {

    private static final Log log = LogFactory.getLog(ArmHook.class);

    private final boolean enablePostCall;

    protected ArmHook() {
        this(false);
    }

    protected ArmHook(boolean enablePostCall) {
        this.enablePostCall = enablePostCall;
    }

    @Override
    public final UnidbgPointer onRegister(SvcMemory svcMemory, int svcNumber) {
        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm, KeystoneMode.Arm)) {
            KeystoneEncoded encoded;
            if (enablePostCall) {
                encoded = keystone.assemble(Arrays.asList(
                        "push {r4-r7, lr}",
                        "svc #0x" + Integer.toHexString(svcNumber),
                        "pop {r7}",
                        "cmp r7, #0",
                        "popeq {r4-r7, pc}",
                        "blx r7",
                        "mov r7, #0",
                        "mov r5, #0x" + Integer.toHexString(Svc.CALLBACK_SYSCALL_NUMBER),
                        "mov r4, #0x" + Integer.toHexString(svcNumber),
                        "svc #0",
                        "pop {r4-r7, pc}"));
            } else {
                encoded = keystone.assemble(Arrays.asList(
                        "svc #0x" + Integer.toHexString(svcNumber),
                        "pop {pc}")); // manipulated stack in handle
            }
            byte[] code = encoded.getMachineCode();
            UnidbgPointer pointer = svcMemory.allocate(code.length, "ArmHook");
            pointer.write(0, code, 0, code.length);
            if (log.isDebugEnabled()) {
                log.debug("ARM hook: pointer=" + pointer);
            }
            return pointer;
        }
    }

    @Override
    public final long handle(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        Pointer sp = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_SP);
        try {
            HookStatus status = hook(emulator);
            if (status.forward || !enablePostCall) {
                sp = sp.share(-4);
                sp.setInt(0, (int) status.jump);
            } else {
                sp = sp.share(-4);
                sp.setInt(0, 0);
            }

            return status.returnValue;
        } finally {
            backend.reg_write(ArmConst.UC_ARM_REG_SP, ((UnidbgPointer) sp).peer);
        }
    }

    protected abstract HookStatus hook(Emulator<?> emulator);

}
