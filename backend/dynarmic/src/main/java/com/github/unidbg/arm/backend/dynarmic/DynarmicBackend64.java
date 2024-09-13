package com.github.unidbg.arm.backend.dynarmic;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.ARMEmulator;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.backend.DynarmicBackend;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import unicorn.Arm64Const;

public class DynarmicBackend64 extends DynarmicBackend {

    private static final Logger log = LoggerFactory.getLogger(DynarmicBackend64.class);

    public DynarmicBackend64(Emulator<?> emulator, Dynarmic dynarmic) {
        super(emulator, dynarmic);
    }

    @Override
    public void callSVC(long pc, int swi) {
        if (log.isDebugEnabled()) {
            log.debug("callSVC pc=0x{}, swi={}", Long.toHexString(pc), swi);
        }
        if (pc == until) {
            emu_stop();
            return;
        }
        interruptHookNotifier.notifyCallSVC(this, ARMEmulator.EXCP_SWI, swi);
    }

    @Override
    public Number reg_read(int regId) throws BackendException {
        try {
            switch (regId) {
                case Arm64Const.UC_ARM64_REG_X0:
                case Arm64Const.UC_ARM64_REG_X1:
                case Arm64Const.UC_ARM64_REG_X2:
                case Arm64Const.UC_ARM64_REG_X3:
                case Arm64Const.UC_ARM64_REG_X4:
                case Arm64Const.UC_ARM64_REG_X5:
                case Arm64Const.UC_ARM64_REG_X6:
                case Arm64Const.UC_ARM64_REG_X7:
                case Arm64Const.UC_ARM64_REG_X8:
                case Arm64Const.UC_ARM64_REG_X9:
                case Arm64Const.UC_ARM64_REG_X10:
                case Arm64Const.UC_ARM64_REG_X11:
                case Arm64Const.UC_ARM64_REG_X12:
                case Arm64Const.UC_ARM64_REG_X13:
                case Arm64Const.UC_ARM64_REG_X14:
                case Arm64Const.UC_ARM64_REG_X15:
                case Arm64Const.UC_ARM64_REG_X16:
                case Arm64Const.UC_ARM64_REG_X17:
                case Arm64Const.UC_ARM64_REG_X18:
                case Arm64Const.UC_ARM64_REG_X19:
                case Arm64Const.UC_ARM64_REG_X20:
                case Arm64Const.UC_ARM64_REG_X21:
                case Arm64Const.UC_ARM64_REG_X22:
                case Arm64Const.UC_ARM64_REG_X23:
                case Arm64Const.UC_ARM64_REG_X24:
                case Arm64Const.UC_ARM64_REG_X25:
                case Arm64Const.UC_ARM64_REG_X26:
                case Arm64Const.UC_ARM64_REG_X27:
                case Arm64Const.UC_ARM64_REG_X28:
                    return dynarmic.reg_read64(regId - Arm64Const.UC_ARM64_REG_X0);
                case Arm64Const.UC_ARM64_REG_SP:
                    return dynarmic.reg_read_sp64();
                case Arm64Const.UC_ARM64_REG_X29:
                    return dynarmic.reg_read64(29);
                case Arm64Const.UC_ARM64_REG_LR:
                    return dynarmic.reg_read64(30);
                case Arm64Const.UC_ARM64_REG_PC:
                    return dynarmic.reg_read_pc64();
                case Arm64Const.UC_ARM64_REG_NZCV:
                    return dynarmic.reg_read_nzcv();
                default:
                    throw new DynarmicException("regId=" + regId);
            }
        } catch (DynarmicException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void reg_write(int regId, Number value) throws BackendException {
        try {
            switch (regId) {
                case Arm64Const.UC_ARM64_REG_X0:
                case Arm64Const.UC_ARM64_REG_X1:
                case Arm64Const.UC_ARM64_REG_X2:
                case Arm64Const.UC_ARM64_REG_X3:
                case Arm64Const.UC_ARM64_REG_X4:
                case Arm64Const.UC_ARM64_REG_X5:
                case Arm64Const.UC_ARM64_REG_X6:
                case Arm64Const.UC_ARM64_REG_X7:
                case Arm64Const.UC_ARM64_REG_X8:
                case Arm64Const.UC_ARM64_REG_X9:
                case Arm64Const.UC_ARM64_REG_X10:
                case Arm64Const.UC_ARM64_REG_X11:
                case Arm64Const.UC_ARM64_REG_X12:
                case Arm64Const.UC_ARM64_REG_X13:
                case Arm64Const.UC_ARM64_REG_X14:
                case Arm64Const.UC_ARM64_REG_X15:
                case Arm64Const.UC_ARM64_REG_X16:
                case Arm64Const.UC_ARM64_REG_X17:
                case Arm64Const.UC_ARM64_REG_X18:
                case Arm64Const.UC_ARM64_REG_X19:
                case Arm64Const.UC_ARM64_REG_X20:
                case Arm64Const.UC_ARM64_REG_X21:
                case Arm64Const.UC_ARM64_REG_X22:
                case Arm64Const.UC_ARM64_REG_X23:
                case Arm64Const.UC_ARM64_REG_X24:
                case Arm64Const.UC_ARM64_REG_X25:
                case Arm64Const.UC_ARM64_REG_X26:
                case Arm64Const.UC_ARM64_REG_X27:
                case Arm64Const.UC_ARM64_REG_X28:
                    dynarmic.reg_write64(regId - Arm64Const.UC_ARM64_REG_X0, value.longValue());
                    break;
                case Arm64Const.UC_ARM64_REG_SP:
                    dynarmic.reg_set_sp64(value.longValue());
                    break;
                case Arm64Const.UC_ARM64_REG_X29:
                    dynarmic.reg_write64(29, value.longValue());
                    break;
                case Arm64Const.UC_ARM64_REG_LR:
                    dynarmic.reg_write64(30, value.longValue());
                    break;
                case Arm64Const.UC_ARM64_REG_TPIDR_EL0:
                    dynarmic.reg_set_tpidr_el0(value.longValue());
                    break;
                case Arm64Const.UC_ARM64_REG_TPIDRRO_EL0:
                    dynarmic.reg_set_tpidrro_el0(value.longValue());
                    break;
                case Arm64Const.UC_ARM64_REG_NZCV:
                    dynarmic.reg_set_nzcv(value.longValue());
                    break;
                default:
                    throw new DynarmicException("regId=" + regId);
            }
        } catch (DynarmicException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public byte[] reg_read_vector(int regId) throws BackendException {
        try {
            if (regId >= Arm64Const.UC_ARM64_REG_Q0 && regId <= Arm64Const.UC_ARM64_REG_Q31) {
                return dynarmic.reg_read_vector(regId - Arm64Const.UC_ARM64_REG_Q0);
            } else {
                throw new UnsupportedOperationException("regId=" + regId);
            }
        } catch (DynarmicException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void reg_write_vector(int regId, byte[] vector) throws BackendException {
        try {
            if (vector.length != 16) {
                throw new IllegalStateException("Invalid vector size");
            }

            if (regId >= Arm64Const.UC_ARM64_REG_Q0 && regId <= Arm64Const.UC_ARM64_REG_Q31) {
                dynarmic.reg_set_vector(regId - Arm64Const.UC_ARM64_REG_Q0, vector);
            } else {
                throw new UnsupportedOperationException("regId=" + regId);
            }
        } catch (DynarmicException e) {
            throw new BackendException(e);
        }
    }

    @Override
    protected byte[] addSoftBreakPoint(long address, int svcNumber, boolean thumb) {
        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian)) {
            KeystoneEncoded encoded = keystone.assemble("brk #" + svcNumber);
            return encoded.getMachineCode();
        }
    }
}
