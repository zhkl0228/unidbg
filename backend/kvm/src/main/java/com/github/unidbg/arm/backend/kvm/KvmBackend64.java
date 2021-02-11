package com.github.unidbg.arm.backend.kvm;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.*;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import unicorn.Arm64Const;
import unicorn.Unicorn;

public class KvmBackend64 extends KvmBackend {

    public KvmBackend64(Emulator<?> emulator, Kvm kvm) throws BackendException {
        super(emulator, kvm);
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
                case Arm64Const.UC_ARM64_REG_CPACR_EL1:
                    return kvm.reg_read_cpacr_el1();
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
                case Arm64Const.UC_ARM64_REG_CPACR_EL1:
                    kvm.reg_set_cpacr_el1(value.longValue());
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
    public byte[] mem_read(long address, long size) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void mem_write(long address, byte[] bytes) throws BackendException {
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
        throw new UnsupportedOperationException();
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
    public void hook_add_new(InterruptHook callback, Object user_data) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public Unicorn.UnHook hook_add_new(BlockHook callback, long begin, long end, Object user_data) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void emu_start(long begin, long until, long timeout, long count) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void emu_stop() throws BackendException {
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
