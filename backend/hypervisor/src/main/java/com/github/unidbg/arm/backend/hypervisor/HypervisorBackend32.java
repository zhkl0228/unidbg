package com.github.unidbg.arm.backend.hypervisor;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.backend.HypervisorBackend;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.ArmConst;

public class HypervisorBackend32 extends HypervisorBackend {

    private static final Log log = LogFactory.getLog(HypervisorBackend32.class);

    public HypervisorBackend32(Emulator<?> emulator, Hypervisor hypervisor) throws BackendException {
        super(emulator, hypervisor);
    }

    @Override
    public boolean handleException(long esr, long far, long elr, long spsr) {
        int ec = (int) ((esr >> 26) & 0x3f);
        if (log.isDebugEnabled()) {
            log.debug("handleException syndrome=0x" + Long.toHexString(esr) + ", far=0x" + Long.toHexString(far) + ", elr=0x" + Long.toHexString(elr) + ", spsr=0x" + Long.toHexString(spsr) + ", ec=0x" + Integer.toHexString(ec));
        }
        switch (ec) {
            case EC_AA64_SVC: {
                int swi = (int) (esr & 0xffff);
                if (swi == 0 && elr == REG_VBAR_EL1 + 4) {
//                    hypervisor.reg_set_spsr_el1(spsr | (1L << 4));
                    return true;
                }

                callSVC(elr, swi);
                return true;
            }
            case EC_DATAABORT:
            default:
                throw new UnsupportedOperationException("handleException ec=0x" + Integer.toHexString(ec));
        }
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
                case ArmConst.UC_ARM_REG_R0:
                case ArmConst.UC_ARM_REG_R1:
                case ArmConst.UC_ARM_REG_R2:
                case ArmConst.UC_ARM_REG_R3:
                    hypervisor.reg_write64(regId - ArmConst.UC_ARM_REG_R0, value.longValue() & 0xffffffffL);
                    break;
                case ArmConst.UC_ARM_REG_SP:
                    hypervisor.reg_set_sp64(value.longValue() & 0xffffffffL);
                    break;
                case ArmConst.UC_ARM_REG_LR:
                    hypervisor.reg_write64(14, value.longValue() & 0xffffffffL);
                    break;
                case ArmConst.UC_ARM_REG_C13_C0_3:
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
                    return (int) (hypervisor.reg_read64(regId - ArmConst.UC_ARM_REG_R0) & 0xffffffffL);
                case ArmConst.UC_ARM_REG_SP:
                    return hypervisor.reg_read_sp64() & 0xffffffffL;
                case ArmConst.UC_ARM_REG_LR:
                    return hypervisor.reg_read64(14);
                case ArmConst.UC_ARM_REG_PC:
                    return hypervisor.reg_read_pc64();
                case ArmConst.UC_ARM_REG_CPSR:
                    return hypervisor.reg_read_nzcv();
                default:
                    throw new HypervisorException("regId=" + regId);
            }
        } catch (HypervisorException e) {
            throw new BackendException(e);
        }
    }

    @Override
    protected byte[] addSoftBreakPoint(long address, int svcNumber, boolean thumb) {
        throw new UnsupportedOperationException();
    }
}
