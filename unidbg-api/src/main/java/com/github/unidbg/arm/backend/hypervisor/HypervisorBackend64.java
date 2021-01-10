package com.github.unidbg.arm.backend.hypervisor;

import capstone.Arm64;
import capstone.Arm64_const;
import capstone.Capstone;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.backend.HypervisorBackend;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;

public class HypervisorBackend64 extends HypervisorBackend {

    private static final Log log = LogFactory.getLog(HypervisorBackend64.class);

    private final Capstone capstone;

    public HypervisorBackend64(Emulator<?> emulator, Hypervisor hypervisor) throws BackendException {
        super(emulator, hypervisor);

        this.capstone = new Capstone(Capstone.CS_ARCH_ARM64, Capstone.CS_MODE_ARM);
        this.capstone.setDetail(Capstone.CS_OPT_ON);
    }

    @Override
    public boolean handleException(long esr, long far, long elr) {
        if (log.isDebugEnabled()) {
            log.debug("handleException syndrome=0x" + Long.toHexString(esr) + ", far=0x" + Long.toHexString(far) + ", elr=0x" + Long.toHexString(elr));
        }
        int ec = (int) ((esr >> 26) & 0x3f);
        switch (ec) {
            case EC_DATAABORT: {
                boolean isv = (esr & ARM_EL_ISV) != 0;
                boolean isWrite = ((esr >> 6) & 1) != 0;
                boolean s1ptw = ((esr >> 7) & 1) != 0;
                int sas = (int) ((esr >> 22) & 3);
                int len = 1 << sas;
                int srt = (int) ((esr >> 16) & 0x1f);
                int dfsc = (int) (esr & 0x3f);
                if (log.isDebugEnabled()) {
                    log.debug("handle EC_DATAABORT isv=" + isv + ", isWrite=" + isWrite + ", s1ptw=" + s1ptw + ", len=" + len + ", srt=" + srt + ", dfsc=0x" + Integer.toHexString(dfsc) + ", vaddr=0x" + Long.toHexString(far));
                }
                if(dfsc == 0x35) { // IMPLEMENTATION DEFINED fault (Unsupported Exclusive or Atomic access).
                    return handleExclusiveAccess(far, elr);
                }
                throw new UnsupportedOperationException("handleException ec=0x" + Integer.toHexString(ec) + ", dfsc=0x" + Integer.toHexString(dfsc));
            }
            default:
                throw new UnsupportedOperationException("handleException ec=0x" + Integer.toHexString(ec));
        }
    }

    private final ExclusiveMonitor exclusiveMonitor = new ExclusiveMonitor();

    private boolean handleExclusiveAccess(long vaddr, long elr) {
        Pointer pointer = UnidbgPointer.pointer(emulator, vaddr);
        assert pointer != null;
        Pointer pc = UnidbgPointer.pointer(emulator, elr);
        assert pc != null;
        byte[] code = pc.getByteArray(0, 4);
        Capstone.CsInsn insn = capstone.disasm(code, elr, 1)[0];
        if (log.isDebugEnabled()) {
            log.debug("handleExclusiveAccess vaddr=0x" + Long.toHexString(vaddr) + ", elr=0x" + Long.toHexString(elr) + ", asm=" + insn.mnemonic + " " + insn.opStr);
        }
        switch (insn.mnemonic) {
            case "ldaxrh": {
                Arm64.OpInfo opInfo = (Arm64.OpInfo) insn.operands;
                Arm64.Operand operand = opInfo.op[0];
                Arm64.OpValue value = operand.value;
                exclusiveMonitor.loadAcquireExclusive(pointer, 2);
                reg_write(value.reg, pointer.getShort(0) & 0xffffffffL);
                hypervisor.reg_set_elr_el1(elr + 4);
                return true;
            }
            case "ldaxr": {
                Arm64.OpInfo opInfo = (Arm64.OpInfo) insn.operands;
                Arm64.Operand operand = opInfo.op[0];
                Arm64.OpValue value = operand.value;
                if (value.reg >= Arm64_const.ARM64_REG_X0 && value.reg <= Arm64_const.ARM64_REG_X28) {
                    exclusiveMonitor.loadAcquireExclusive(pointer, 8);
                    reg_write(value.reg, pointer.getLong(0));
                } else {
                    exclusiveMonitor.loadAcquireExclusive(pointer, 4);
                    reg_write(value.reg, pointer.getInt(0) & 0xffffffffL);
                }
                hypervisor.reg_set_elr_el1(elr + 4);
                return true;
            }
            case "stxr": {
                Arm64.OpInfo opInfo = (Arm64.OpInfo) insn.operands;
                Arm64.Operand o1 = opInfo.op[0];
                Arm64.Operand o2 = opInfo.op[1];
                Arm64.OpValue ws = o1.value;
                Arm64.OpValue wt = o2.value;
                Number value = reg_read(wt.reg);
                if (wt.reg >= Arm64_const.ARM64_REG_X0 && wt.reg <= Arm64_const.ARM64_REG_X28) {
                    boolean success = exclusiveMonitor.storeExclusive(pointer, 8);
                    exclusiveMonitor.loadAcquireExclusive(pointer, 8);
                    reg_write(ws.reg, success ? 0 : 1);
                    pointer.setLong(0, value.longValue());
                } else {
                    boolean success = exclusiveMonitor.storeExclusive(pointer, 4);
                    reg_write(ws.reg, success ? 0 : 1);
                    pointer.setInt(0, value.intValue());
                }
                hypervisor.reg_set_elr_el1(elr + 4);
                return true;
            }
            default:
                throw new UnsupportedOperationException(insn.mnemonic);
        }
    }

    @Override
    public void enableVFP() {
        long value = reg_read(Arm64Const.UC_ARM64_REG_CPACR_EL1).longValue();
        value |= 0x300000; // set the FPEN bits
        reg_write(Arm64Const.UC_ARM64_REG_CPACR_EL1, value);
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
                case Arm64Const.UC_ARM64_REG_W3:
                case Arm64Const.UC_ARM64_REG_W4:
                case Arm64Const.UC_ARM64_REG_W5:
                case Arm64Const.UC_ARM64_REG_W11:
                    hypervisor.reg_write64(regId - Arm64Const.UC_ARM64_REG_W0, value.longValue());
                    break;
                case Arm64Const.UC_ARM64_REG_SP:
                    hypervisor.reg_set_sp64(value.longValue());
                    break;
                case Arm64Const.UC_ARM64_REG_LR:
                    hypervisor.reg_write64(30, value.longValue());
                    break;
                case Arm64Const.UC_ARM64_REG_TPIDR_EL0:
                    hypervisor.reg_set_tpidr_el0(value.longValue());
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
                    return hypervisor.reg_read64(regId - Arm64Const.UC_ARM64_REG_X0);
                case Arm64Const.UC_ARM64_REG_W4:
                    return (int) (hypervisor.reg_read64(regId - Arm64Const.UC_ARM64_REG_W0) & 0xffffffffL);
                case Arm64Const.UC_ARM64_REG_SP:
                    return hypervisor.reg_read_sp64();
                case Arm64Const.UC_ARM64_REG_FP:
                    return hypervisor.reg_read64(29);
                case Arm64Const.UC_ARM64_REG_LR:
                    return hypervisor.reg_read64(30);
                case Arm64Const.UC_ARM64_REG_PC:
                    return hypervisor.reg_read_pc64();
                case Arm64Const.UC_ARM64_REG_NZCV:
                    return hypervisor.reg_read_nzcv();
                case Arm64Const.UC_ARM64_REG_CPACR_EL1:
                    return hypervisor.reg_read_cpacr_el1();
                default:
                    throw new HypervisorException("regId=" + regId);
            }
        } catch (HypervisorException e) {
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
