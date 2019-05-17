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
import unicorn.Arm64Const;
import unicorn.Unicorn;

import java.util.Arrays;

public abstract class Arm64Hook extends Arm64Svc {

    private static final Log log = LogFactory.getLog(Arm64Hook.class);

    @Override
    public final UnicornPointer onRegister(SvcMemory svcMemory, int svcNumber) {
        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian)) {
            KeystoneEncoded encoded = keystone.assemble(Arrays.asList(
                    "svc #0x" + Integer.toHexString(svcNumber),
                    "ldr x17, [sp], #0x8",
                    "br x17")); // manipulated stack in handle
            byte[] code = encoded.getMachineCode();
            UnicornPointer pointer = svcMemory.allocate(code.length);
            pointer.write(0, code, 0, code.length);
            log.debug("ARM64 hook: pointer=" + pointer);
            return pointer;
        }
    }

    @Override
    public final int handle(Emulator emulator) {
        Unicorn u = emulator.getUnicorn();
        Pointer sp = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_SP);
        try {
            HookStatus status = hook(u, emulator);
            sp = sp.share(-8);
            sp.setLong(0, status.jump);

            return (int) status.returnValue;
        } finally {
            u.reg_write(Arm64Const.UC_ARM64_REG_SP, ((UnicornPointer) sp).peer);
        }
    }

    protected abstract HookStatus hook(Unicorn u, Emulator emulator);

}
