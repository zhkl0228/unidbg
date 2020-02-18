package com.github.unidbg.arm;

import com.github.unidbg.Emulator;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.ArmConst;
import unicorn.Unicorn;

import java.util.Arrays;

public abstract class ArmHook extends ArmSvc {

    private static final Log log = LogFactory.getLog(ArmHook.class);

    @Override
    public final UnicornPointer onRegister(SvcMemory svcMemory, int svcNumber) {
        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm, KeystoneMode.Arm)) {
            KeystoneEncoded encoded = keystone.assemble(Arrays.asList(
                    "push {r4-r7, lr}",
                    "svc #0x" + Integer.toHexString(svcNumber),
                    "pop {r7}",
                    "cmp r7, #0",
                    "popeq {r1, r4-r7, pc}",
                    "pop {r7}",
                    "blx r7",
                    "mov r7, #0",
                    "mov r4, #0x" + Integer.toHexString(svcNumber),
                    "svc #0",
                    "pop {r4-r7, pc}"));
            byte[] code = encoded.getMachineCode();
            UnicornPointer pointer = svcMemory.allocate(code.length, "ArmHook");
            pointer.write(0, code, 0, code.length);
            if (log.isDebugEnabled()) {
                log.debug("ARM hook: pointer=" + pointer);
            }
            return pointer;
        }
    }

    @Override
    public final long handle(Emulator emulator) {
        Unicorn u = emulator.getUnicorn();
        Pointer sp = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_SP);
        try {
            HookStatus status = hook(emulator);
            if (status.forward) {
                sp = sp.share(-4);
                sp.setInt(0, (int) status.jump);

                sp = sp.share(-4);
                sp.setInt(0, 1);
            } else {
                sp = sp.share(-4);
                sp.setInt(0, (int) status.r1);

                sp = sp.share(-4);
                sp.setInt(0, 0);
            }

            return status.r0;
        } finally {
            u.reg_write(ArmConst.UC_ARM_REG_SP, ((UnicornPointer) sp).peer);
        }
    }

    protected abstract HookStatus hook(Emulator emulator);

}
