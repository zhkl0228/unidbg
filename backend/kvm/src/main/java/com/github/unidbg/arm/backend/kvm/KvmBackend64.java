package com.github.unidbg.arm.backend.kvm;

import capstone.api.Disassembler;
import capstone.api.DisassemblerFactory;
import capstone.api.Instruction;
import capstone.api.arm64.OpInfo;
import capstone.api.arm64.OpValue;
import capstone.api.arm64.Operand;
import com.alibaba.fastjson.util.IOUtils;
import com.github.unidbg.Emulator;
import com.github.unidbg.Family;
import com.github.unidbg.arm.ARMEmulator;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.backend.DebugHook;
import com.github.unidbg.arm.backend.KvmBackend;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import unicorn.Arm64Const;
import unicorn.UnicornConst;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class KvmBackend64 extends KvmBackend {

    private static final Logger log = LoggerFactory.getLogger(KvmBackend64.class);

    private static final int EC_AA64_SVC = 0x15;
    private static final int EC_AA64_BKPT = 0x3c;

    private static final long DARWIN_KERNEL_BASE = 0xffffff80001f0000L;
    private static final long _COMM_PAGE64_BASE_ADDRESS = DARWIN_KERNEL_BASE + 0xc000 /* In TTBR0 */;

    public KvmBackend64(Emulator<?> emulator, Kvm kvm) throws BackendException {
        super(emulator, kvm);
    }

    @Override
    public void onInitialize() {
        super.onInitialize();

        mem_map(REG_VBAR_EL1, getPageSize(), UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_EXEC);
        ByteBuffer buffer = ByteBuffer.allocate(getPageSize());
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        while (buffer.hasRemaining()) {
            if (buffer.position() == 0x400) {
                buffer.putInt(0x390003e0); // strb w0, [sp]
            } else {
                buffer.putInt(0x390003e1); // strb w1, [sp]
            }
            if (buffer.hasRemaining()) {
                buffer.putInt(0xd69f03e0); // eret
            }
        }
        UnidbgPointer ptr = UnidbgPointer.pointer(emulator, REG_VBAR_EL1);
        assert ptr != null;
        ptr.write(buffer.array());
    }

    private Disassembler disassembler;

    private synchronized Disassembler createDisassembler() {
        if (disassembler == null) {
            this.disassembler = DisassemblerFactory.createArm64Disassembler();
            this.disassembler.setDetail(true);
        }
        return disassembler;
    }

    private void handleCommRead(long vaddr, long elr) {
        Pointer pointer = UnidbgPointer.pointer(emulator, vaddr);
        assert pointer != null;
        Pointer pc = UnidbgPointer.pointer(emulator, elr);
        assert pc != null;
        byte[] code = pc.getByteArray(0, 4);
        Instruction insn = createDisassembler().disasm(code, elr, 1)[0];
        if (log.isDebugEnabled()) {
            log.debug("handleCommRead vaddr=0x{}, elr=0x{}, asm={}", Long.toHexString(vaddr), Long.toHexString(elr), insn);
        }
        OpInfo opInfo = (OpInfo) insn.getOperands();
        if (opInfo.isUpdateFlags() || opInfo.isWriteBack() || !insn.getMnemonic().startsWith("ldr") || vaddr < _COMM_PAGE64_BASE_ADDRESS) {
            throw new UnsupportedOperationException();
        }
        Operand[] op = opInfo.getOperands();
        int offset = (int) (vaddr - _COMM_PAGE64_BASE_ADDRESS);
        switch (offset) {
            case 0x38: // uint64_t max memory size */
            case 0x40:
            case 0x58: {
                Operand operand = op[0];
                OpValue value = operand.getValue();
                reg_write(insn.mapToUnicornReg(value.getReg()), 0x0L);
                kvm.reg_set_elr_el1(elr + 4);
                return;
            }
            case 0x48:
            case 0x4c:
            case 0x50:
            case 0x60:
            case 0x64:
            case 0x90: {
                Operand operand = op[0];
                OpValue value = operand.getValue();
                reg_write(insn.mapToUnicornReg(value.getReg()), 0x0);
                kvm.reg_set_elr_el1(elr + 4);
                return;
            }
            case 0x22: // uint8_t number of configured CPUs
            case 0x34: // uint8_t number of active CPUs (hw.activecpu)
            case 0x35: // uint8_t number of physical CPUs (hw.physicalcpu_max)
            case 0x36: { // uint8_t number of logical CPUs (hw.logicalcpu_max)
                Operand operand = op[0];
                OpValue value = operand.getValue();
                reg_write(insn.mapToUnicornReg(value.getReg()), 1);
                kvm.reg_set_elr_el1(elr + 4);
                return;
            }
            default:
                throw new UnsupportedOperationException("vaddr=0x" + Long.toHexString(vaddr));
        }
    }

    @Override
    public boolean handleException(long esr, long far, long elr, long spsr, long pc) {
        int ec = (int) ((esr >> 26) & 0x3f);
        if (log.isDebugEnabled()) {
            log.debug("handleException syndrome=0x{}, far=0x{}, elr=0x{}, ec=0x{}, pc=0x{}", Long.toHexString(esr), Long.toHexString(far), Long.toHexString(elr), Integer.toHexString(ec), Long.toHexString(pc));
        }
        switch (ec) {
            case EC_AA64_SVC: {
                int swi = (int) (esr & 0xffff);
                callSVC(elr, swi);
                return true;
            }
            case EC_AA64_BKPT: {
                int bkpt = (int) (esr & 0xffff);
                interruptHookNotifier.notifyCallSVC(this, ARMEmulator.EXCP_BKPT, bkpt);
                return true;
            }
            case EC_DATAABORT: {
                boolean isv = (esr & ARM_EL_ISV) != 0;
                boolean isWrite = ((esr >> 6) & 1) != 0;
                boolean s1ptw = ((esr >> 7) & 1) != 0;
                int sas = (int) ((esr >> 22) & 3);
                int len = 1 << sas;
                int srt = (int) ((esr >> 16) & 0x1f);
                int dfsc = (int) (esr & 0x3f);
                if (log.isDebugEnabled()) {
                    log.debug("handle EC_DATAABORT isv={}, isWrite={}, s1ptw={}, len={}, srt={}, dfsc=0x{}, vaddr=0x{}", isv, isWrite, s1ptw, len, srt, Integer.toHexString(dfsc), Long.toHexString(far));
                }
                if (dfsc == 0x00 && emulator.getFamily() == Family.iOS) {
                    handleCommRead(far, elr);
                    return true;
                }
                throw new UnsupportedOperationException("handleException ec=0x" + Integer.toHexString(ec) + ", dfsc=0x" + Integer.toHexString(dfsc));
            }
            default:
                throw new UnsupportedOperationException("handleException ec=0x" + Integer.toHexString(ec));
        }
    }

    @Override
    public void mem_map(long address, long size, int perms) throws BackendException {
        if (address == DARWIN_KERNEL_BASE) {
            throw new BackendException();
        }

        super.mem_map(address, size, perms);
    }

    @Override
    public void switchUserMode() {
    }

    @Override
    public void enableVFP() {
        long value = reg_read(Arm64Const.UC_ARM64_REG_CPACR_EL1).longValue();
        value |= 0x300000; // set the FPEN bits
        reg_write(Arm64Const.UC_ARM64_REG_CPACR_EL1, value);
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
                    return kvm.reg_read64(regId - Arm64Const.UC_ARM64_REG_X0);
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
                    return (int) (kvm.reg_read64(regId - Arm64Const.UC_ARM64_REG_W0) & 0xffffffffL);
                case Arm64Const.UC_ARM64_REG_CPACR_EL1:
                    return kvm.reg_read_cpacr_el1();
                case Arm64Const.UC_ARM64_REG_SP:
                    return kvm.reg_read_sp64();
                case Arm64Const.UC_ARM64_REG_PC:
                    return kvm.reg_read_pc64();
                case Arm64Const.UC_ARM64_REG_FP:
                    return kvm.reg_read64(29);
                case Arm64Const.UC_ARM64_REG_LR:
                    return kvm.reg_read64(30);
                case Arm64Const.UC_ARM64_REG_NZCV:
                    return kvm.reg_read_nzcv();
                default:
                    throw new KvmException("regId=" + regId);
            }
        } catch (KvmException e) {
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
                    kvm.reg_write64(regId - Arm64Const.UC_ARM64_REG_X0, value.longValue());
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
                    kvm.reg_write64(regId - Arm64Const.UC_ARM64_REG_W0, value.longValue());
                    break;
                case Arm64Const.UC_ARM64_REG_CPACR_EL1:
                    kvm.reg_set_cpacr_el1(value.longValue());
                    break;
                case Arm64Const.UC_ARM64_REG_SP:
                    kvm.reg_set_sp64(value.longValue());
                    break;
                case Arm64Const.UC_ARM64_REG_X29:
                    kvm.reg_write64(29, value.longValue());
                    break;
                case Arm64Const.UC_ARM64_REG_TPIDR_EL0:
                    kvm.reg_set_tpidr_el0(value.longValue());
                    break;
                case Arm64Const.UC_ARM64_REG_LR:
                    kvm.reg_write64(30, value.longValue());
                    break;
                case Arm64Const.UC_ARM64_REG_TPIDRRO_EL0:
                    kvm.reg_set_tpidrro_el0(value.longValue());
                    break;
                case Arm64Const.UC_ARM64_REG_NZCV:
                    kvm.reg_set_nzcv(value.longValue());
                    break;
                default:
                    throw new KvmException("regId=" + regId);
            }
        } catch (KvmException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public byte[] reg_read_vector(int regId) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void reg_write_vector(int regId, byte[] vector) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void debugger_add(DebugHook callback, long begin, long end, Object user_data) throws BackendException {
    }

    @Override
    protected byte[] addSoftBreakPoint(long address, int svcNumber, boolean thumb) {
        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian)) {
            KeystoneEncoded encoded = keystone.assemble("brk #" + svcNumber);
            return encoded.getMachineCode();
        }
    }

    @Override
    public synchronized void destroy() throws BackendException {
        super.destroy();

        IOUtils.close(disassembler);
        disassembler = null;
    }
}
