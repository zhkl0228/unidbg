package com.github.unidbg.arm.backend.hypervisor;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.backend.HypervisorBackend;
import unicorn.Arm64Const;
import unicorn.ArmConst;

public class HypervisorBackend32 extends HypervisorBackend {

    public HypervisorBackend32(Emulator<?> emulator, Hypervisor hypervisor) throws BackendException {
        super(emulator, hypervisor);
    }

    @Override
    public boolean handleException(long esr, long far, long elr) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void enableVFP() {
    }

    @Override
    public void switchUserMode() {
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
                    hypervisor.reg_write64(regId - Arm64Const.UC_ARM64_REG_X0, value.longValue());
                    break;
                case Arm64Const.UC_ARM64_REG_W0:
                case Arm64Const.UC_ARM64_REG_W1:
                case Arm64Const.UC_ARM64_REG_W2:
                case Arm64Const.UC_ARM64_REG_W3:
                case Arm64Const.UC_ARM64_REG_W4:
                case Arm64Const.UC_ARM64_REG_W5:
                case Arm64Const.UC_ARM64_REG_W6:
                case Arm64Const.UC_ARM64_REG_W7:
                case Arm64Const.UC_ARM64_REG_W8:
                case Arm64Const.UC_ARM64_REG_W9:
                case Arm64Const.UC_ARM64_REG_W10:
                case Arm64Const.UC_ARM64_REG_W11:
                case Arm64Const.UC_ARM64_REG_W12:
                case Arm64Const.UC_ARM64_REG_W13:
                case Arm64Const.UC_ARM64_REG_W14:
                case Arm64Const.UC_ARM64_REG_W15:
                case Arm64Const.UC_ARM64_REG_W16:
                case Arm64Const.UC_ARM64_REG_W17:
                case Arm64Const.UC_ARM64_REG_W18:
                case Arm64Const.UC_ARM64_REG_W19:
                case Arm64Const.UC_ARM64_REG_W20:
                case Arm64Const.UC_ARM64_REG_W21:
                case Arm64Const.UC_ARM64_REG_W22:
                case Arm64Const.UC_ARM64_REG_W23:
                case Arm64Const.UC_ARM64_REG_W24:
                case Arm64Const.UC_ARM64_REG_W25:
                case Arm64Const.UC_ARM64_REG_W26:
                case Arm64Const.UC_ARM64_REG_W27:
                case Arm64Const.UC_ARM64_REG_W28:
                case Arm64Const.UC_ARM64_REG_W29:
                case Arm64Const.UC_ARM64_REG_W30:
                    hypervisor.reg_write64(regId - Arm64Const.UC_ARM64_REG_W0, value.longValue());
                    break;
                case ArmConst.UC_ARM_REG_SP:
                    hypervisor.reg_set_sp64(value.longValue() & 0xffffffffL);
                    break;
                case Arm64Const.UC_ARM64_REG_LR:
                    hypervisor.reg_write64(30, value.longValue());
                    break;
                case ArmConst.UC_ARM_REG_C13_C0_3:
                    break;
                case Arm64Const.UC_ARM64_REG_TPIDRRO_EL0:
                    hypervisor.reg_set_tpidrro_el0(value.longValue());
                    break;
                case Arm64Const.UC_ARM64_REG_NZCV:
                    hypervisor.reg_set_nzcv(value.longValue());
                    break;
                case Arm64Const.UC_ARM64_REG_CPACR_EL1:
                    hypervisor.reg_set_cpacr_el1(value.longValue());
                    break;
                default:
                    throw new HypervisorException("regId=" + regId);
            }
        } catch (HypervisorException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public Number reg_read(int regId) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    protected byte[] addSoftBreakPoint(long address, int svcNumber, boolean thumb) {
        throw new UnsupportedOperationException();
    }
}
