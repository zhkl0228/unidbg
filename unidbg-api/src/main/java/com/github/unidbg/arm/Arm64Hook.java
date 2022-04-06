package com.github.unidbg.arm;

import com.github.unidbg.Emulator;
import com.github.unidbg.Svc;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public abstract class Arm64Hook extends Arm64Svc {

    private static final Log log = LogFactory.getLog(Arm64Hook.class);

    private final boolean enablePostCall;

    protected Arm64Hook() {
        this(false);
    }

    protected Arm64Hook(boolean enablePostCall) {
        this.enablePostCall = enablePostCall;
    }

    public Arm64Hook(String name, boolean enablePostCall) {
        super(name);
        this.enablePostCall = enablePostCall;
    }

    @Override
    public final UnidbgPointer onRegister(SvcMemory svcMemory, int svcNumber) {
        byte[] code;
        if (enablePostCall) {
            try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian)) {
                KeystoneEncoded encoded = keystone.assemble(Arrays.asList(
                        "svc #0x" + Integer.toHexString(svcNumber),

                        "ldr x13, [sp]",
                        "add sp, sp, #0x8",
                        "cmp x13, #0",
                        "b.eq #0x30",
                        "blr x13",
                        "mov x8, #0",
                        "mov x12, #0x" + Integer.toHexString(svcNumber),
                        "mov x16, #0x" + Integer.toHexString(Svc.POST_CALLBACK_SYSCALL_NUMBER),
                        "svc #0",

                        "ret"));
                code = encoded.getMachineCode();
            }
        } else {
            ByteBuffer buffer = ByteBuffer.allocate(12);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putInt(Arm64Svc.assembleSvc(svcNumber)); // svc #0xsvcNumber
            buffer.putInt(0xf84087f1); // ldr x17, [sp], #0x8
            buffer.putInt(0xd61f0220); // br x17: manipulated stack in handle
            code = buffer.array();
        }
        String name = getName();
        UnidbgPointer pointer = svcMemory.allocate(code.length, name == null ? "Arm64Hook" : name);
        pointer.write(0, code, 0, code.length);
        if (log.isDebugEnabled()) {
            log.debug("ARM64 hook: pointer=" + pointer);
        }
        return pointer;
    }

    @Override
    public void handlePostCallback(Emulator<?> emulator) {
        super.handlePostCallback(emulator);

        if (regContext == null) {
            throw new IllegalStateException();
        } else {
            regContext.restore();
        }
    }

    private RegContext regContext;

    @Override
    public final long handle(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        if (enablePostCall) {
            regContext = RegContext.backupContext(emulator, Arm64Const.UC_ARM64_REG_X29,
                    Arm64Const.UC_ARM64_REG_X30);
        }
        UnidbgPointer sp = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_SP);
        try {
            HookStatus status = hook(emulator);
            if (status.forward || !enablePostCall) {
                sp = sp.share(-8, 0);
                sp.setLong(0, status.jump);
            } else {
                sp = sp.share(-8, 0);
                sp.setLong(0, 0);
            }

            return status.returnValue;
        } finally {
            backend.reg_write(Arm64Const.UC_ARM64_REG_SP, sp.peer);
        }
    }

    protected abstract HookStatus hook(Emulator<?> emulator);

}
