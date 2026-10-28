package com.github.unidbg.linux;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.arm.ARMEmulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import org.junit.Test;
import unicorn.Arm64Const;
import unicorn.ArmConst;

import static org.junit.Assert.assertEquals;

public class PrctlTest {

    private static final int PR_GET_DUMPABLE = 3;
    private static final int PR_SET_DUMPABLE = 4;
    private static final int PR_SET_NO_NEW_PRIVS = 38;
    private static final int PR_GET_NO_NEW_PRIVS = 39;
    private static final int PR_SET_THP_DISABLE = 41;

    @Test
    public void arm64() throws Exception {
        try (AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit().addBackendFactory(new Unicorn2Factory(true)).build()) {
            check(emulator);
        }
    }

    @Test
    public void arm32() throws Exception {
        try (AndroidEmulator emulator = AndroidEmulatorBuilder.for32Bit().addBackendFactory(new Unicorn2Factory(true)).build()) {
            check(emulator);
        }
    }

    private void check(AndroidEmulator emulator) {
        assertEquals(0, prctl(emulator, PR_GET_DUMPABLE, 0)); // 应用进程默认 dumpable=0
        assertEquals(0, prctl(emulator, PR_SET_DUMPABLE, 0));
        assertEquals(0, prctl(emulator, PR_GET_DUMPABLE, 0));
        assertEquals(0, prctl(emulator, PR_SET_DUMPABLE, 1));
        assertEquals(1, prctl(emulator, PR_GET_DUMPABLE, 0));

        assertEquals(0, prctl(emulator, PR_GET_NO_NEW_PRIVS, 0));
        assertEquals(0, prctl(emulator, PR_SET_NO_NEW_PRIVS, 1));
        assertEquals(1, prctl(emulator, PR_GET_NO_NEW_PRIVS, 0));
        assertEquals(0, prctl(emulator, PR_SET_THP_DISABLE, 1));
    }

    private static int prctl(AndroidEmulator emulator, int option, long arg2) {
        Backend backend = emulator.getBackend();
        if (emulator.is64Bit()) {
            backend.reg_write(Arm64Const.UC_ARM64_REG_X0, option);
            backend.reg_write(Arm64Const.UC_ARM64_REG_X1, arg2);
            backend.reg_write(Arm64Const.UC_ARM64_REG_X8, 167); // __NR_prctl
        } else {
            backend.reg_write(ArmConst.UC_ARM_REG_R0, option);
            backend.reg_write(ArmConst.UC_ARM_REG_R1, (int) arg2);
            backend.reg_write(ArmConst.UC_ARM_REG_R7, 172); // __NR_prctl
        }
        emulator.getSyscallHandler().hook(backend, ARMEmulator.EXCP_SWI, 0, emulator);
        if (emulator.is64Bit()) {
            return backend.reg_read(Arm64Const.UC_ARM64_REG_X0).intValue();
        }
        return backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
    }

}
