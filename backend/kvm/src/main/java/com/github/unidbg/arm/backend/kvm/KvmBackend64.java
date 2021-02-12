package com.github.unidbg.arm.backend.kvm;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.*;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;
import unicorn.Unicorn;

public class KvmBackend64 extends KvmBackend {

    private static final Log log = LogFactory.getLog(KvmBackend64.class);

    public KvmBackend64(Emulator<?> emulator, Kvm kvm) throws BackendException {
        super(emulator, kvm);
    }

    @Override
    public boolean handleException(long esr, long far, long elr, long spsr) {
        int ec = (int) ((esr >> 26) & 0x3f);
        if (log.isDebugEnabled()) {
            log.debug("handleException syndrome=0x" + Long.toHexString(esr) + ", far=0x" + Long.toHexString(far) + ", elr=0x" + Long.toHexString(elr) + ", ec=0x" + Integer.toHexString(ec));
        }
        throw new IllegalStateException();
    }

    @Override
    public synchronized void emu_start(long begin, long until, long timeout, long count) throws BackendException {
        emulator.attach().disassembleBlock(emulator, begin, false);

        super.emu_start(begin, until, timeout, count);
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
                case Arm64Const.UC_ARM64_REG_CPACR_EL1:
                    return kvm.reg_read_cpacr_el1();
                case Arm64Const.UC_ARM64_REG_SP:
                    return kvm.reg_read_sp64();
                case Arm64Const.UC_ARM64_REG_PC:
                    return kvm.reg_read_pc64();
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
                case Arm64Const.UC_ARM64_REG_CPACR_EL1:
                    kvm.reg_set_cpacr_el1(value.longValue());
                    break;
                case Arm64Const.UC_ARM64_REG_SP:
                    kvm.reg_set_sp64(value.longValue());
                    break;
                case Arm64Const.UC_ARM64_REG_TPIDR_EL0:
                    kvm.reg_set_tpidr_el0(value.longValue());
                    break;
                case Arm64Const.UC_ARM64_REG_LR:
                    kvm.reg_write64(30, value.longValue());
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
    public void mem_protect(long address, long size, int perms) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void mem_unmap(long address, long size) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public Unicorn.UnHook hook_add_new(CodeHook callback, long begin, long end, Object user_data) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public Unicorn.UnHook debugger_add(DebugHook callback, long begin, long end, Object user_data) throws BackendException {
        return null;
    }

    @Override
    public void hook_add_new(ReadHook callback, long begin, long end, Object user_data) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void hook_add_new(WriteHook callback, long begin, long end, Object user_data) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public Unicorn.UnHook hook_add_new(BlockHook callback, long begin, long end, Object user_data) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    protected byte[] addSoftBreakPoint(long address, int svcNumber, boolean thumb) {
        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian)) {
            KeystoneEncoded encoded = keystone.assemble("brk #" + svcNumber);
            return encoded.getMachineCode();
        }
    }

}
