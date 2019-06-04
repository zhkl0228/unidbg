package cn.banny.unidbg.arm;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.memory.SvcMemory;
import cn.banny.unidbg.pointer.UnicornPointer;
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
                    "svc #0x" + Integer.toHexString(svcNumber),
                    "pop {pc}")); // manipulated stack in handle
            byte[] code = encoded.getMachineCode();
            UnicornPointer pointer = svcMemory.allocate(code.length, "ArmHook");
            pointer.write(0, code, 0, code.length);
            log.debug("ARM hook: pointer=" + pointer);
            return pointer;
        }
    }

    @Override
    public final long handle(Emulator emulator) {
        Unicorn u = emulator.getUnicorn();
        Pointer sp = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_SP);
        try {
            HookStatus status = hook(emulator);
            sp = sp.share(-4);
            sp.setInt(0, (int) status.jump);

            return status.returnValue;
        } finally {
            u.reg_write(ArmConst.UC_ARM_REG_SP, ((UnicornPointer) sp).peer);
        }
    }

    protected abstract HookStatus hook(Emulator emulator);

}
