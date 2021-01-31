package com.github.unidbg.arm.backend.dynarmic;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.ARMEmulator;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.backend.DynarmicBackend;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.ArmConst;

public class DynarmicBackend32 extends DynarmicBackend {

    private static final Log log = LogFactory.getLog(DynarmicBackend32.class);

    public DynarmicBackend32(Emulator<?> emulator, Dynarmic dynarmic) {
        super(emulator, dynarmic);
    }

    @Override
    public void callSVC(long pc, int swi) {
        if (log.isDebugEnabled()) {
            log.debug("callSVC pc=0x" + Long.toHexString(pc) + ", swi=" + swi);
        }
        if (pc == until) {
            emu_stop();
            return;
        }
        interruptHookNotifier.notifyCallSVC(this, ARMEmulator.EXCP_SWI, swi);
    }

    @Override
    public boolean handleInterpreterFallback(long pc, int num_instructions) {
        throw new AbstractMethodError();
    }

    @Override
    public Number reg_read(int regId) throws BackendException {
        try {
            switch (regId) {
                case ArmConst.UC_ARM_REG_R0:
                case ArmConst.UC_ARM_REG_R1:
                case ArmConst.UC_ARM_REG_R2:
                case ArmConst.UC_ARM_REG_R3:
                case ArmConst.UC_ARM_REG_R4:
                case ArmConst.UC_ARM_REG_R5:
                case ArmConst.UC_ARM_REG_R6:
                case ArmConst.UC_ARM_REG_R7:
                case ArmConst.UC_ARM_REG_R8:
                case ArmConst.UC_ARM_REG_R9:
                case ArmConst.UC_ARM_REG_R10:
                case ArmConst.UC_ARM_REG_R11:
                case ArmConst.UC_ARM_REG_R12:
                    return dynarmic.reg_read32(regId - ArmConst.UC_ARM_REG_R0);
                case ArmConst.UC_ARM_REG_SP:
                    return dynarmic.reg_read32(13);
                case ArmConst.UC_ARM_REG_LR:
                    return dynarmic.reg_read32(14);
                case ArmConst.UC_ARM_REG_PC:
                    return dynarmic.reg_read32(15);
                case ArmConst.UC_ARM_REG_CPSR:
                    return dynarmic.reg_read_cpsr();
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
                case ArmConst.UC_ARM_REG_R0:
                case ArmConst.UC_ARM_REG_R1:
                case ArmConst.UC_ARM_REG_R2:
                case ArmConst.UC_ARM_REG_R3:
                case ArmConst.UC_ARM_REG_R4:
                case ArmConst.UC_ARM_REG_R5:
                case ArmConst.UC_ARM_REG_R6:
                case ArmConst.UC_ARM_REG_R7:
                case ArmConst.UC_ARM_REG_R8:
                case ArmConst.UC_ARM_REG_R9:
                case ArmConst.UC_ARM_REG_R10:
                case ArmConst.UC_ARM_REG_R11:
                case ArmConst.UC_ARM_REG_R12:
                    dynarmic.reg_write32(regId - ArmConst.UC_ARM_REG_R0, value.intValue());
                    break;
                case ArmConst.UC_ARM_REG_SP:
                    dynarmic.reg_write32(13, value.intValue());
                    break;
                case ArmConst.UC_ARM_REG_LR:
                    dynarmic.reg_write32(14, value.intValue());
                    break;
                case ArmConst.UC_ARM_REG_C13_C0_3:
                    dynarmic.reg_write_c13_c0_3(value.intValue());
                    break;
                case ArmConst.UC_ARM_REG_CPSR:
                    dynarmic.reg_write_cpsr(value.intValue());
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
        return null;
    }

    @Override
    public void reg_write_vector(int regId, byte[] vector) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    protected byte[] addSoftBreakPoint(long address, int svcNumber, boolean thumb) {
        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm, thumb ? KeystoneMode.ArmThumb : KeystoneMode.Arm)) {
            KeystoneEncoded encoded = keystone.assemble("bkpt #" + svcNumber);
            return encoded.getMachineCode();
        }
    }
}
