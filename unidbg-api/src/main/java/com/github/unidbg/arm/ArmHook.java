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
import unicorn.ArmConst;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
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

    public ArmHook(String name, boolean enablePostCall) {
        super(name);
        this.enablePostCall = enablePostCall;
    }

    @Override
    public final UnidbgPointer onRegister(SvcMemory svcMemory, int svcNumber) {
        byte[] code;
        if (enablePostCall) {
            try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm, KeystoneMode.Arm)) {
                KeystoneEncoded encoded = keystone.assemble(Arrays.asList(
                        "svc #0x" + Integer.toHexString(svcNumber),
                        "pop {r7}",
                        "cmp r7, #0",
                        "bxeq lr",
                        "blx r7",
                        "mov r7, #0",
                        "mov r5, #0x" + Integer.toHexString(Svc.POST_CALLBACK_SYSCALL_NUMBER),
                        "mov r4, #0x" + Integer.toHexString(svcNumber),
                        "svc #0",
                        "bx lr"));
                code = encoded.getMachineCode();
            }
        } else {
            ByteBuffer buffer = ByteBuffer.allocate(8);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putInt(ArmSvc.assembleSvc(svcNumber)); // svc #0xsvcNumber
            buffer.putInt(0xe49df004); // pop {pc}: manipulated stack in handle
            code = buffer.array();
        }
        String name = getName();
        UnidbgPointer pointer = svcMemory.allocate(code.length, name == null ? "ArmHook" : name);
        pointer.write(0, code, 0, code.length);
        if (log.isDebugEnabled()) {
            log.debug("ARM hook: pointer=" + pointer);
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
            regContext = RegContext.backupContext(emulator, ArmConst.UC_ARM_REG_R4,
                    ArmConst.UC_ARM_REG_R5,
                    ArmConst.UC_ARM_REG_R6,
                    ArmConst.UC_ARM_REG_R7,
                    ArmConst.UC_ARM_REG_LR);
        }
        UnidbgPointer sp = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_SP);
        try {
            HookStatus status = hook(emulator);
            if (status.forward || !enablePostCall) {
                sp = sp.share(-4, 0);
                sp.setInt(0, (int) status.jump);
            } else {
                sp = sp.share(-4, 0);
                sp.setInt(0, 0);
            }

            return status.returnValue;
        } finally {
            backend.reg_write(ArmConst.UC_ARM_REG_SP, sp.peer);
        }
    }

    protected abstract HookStatus hook(Emulator<?> emulator);

}
