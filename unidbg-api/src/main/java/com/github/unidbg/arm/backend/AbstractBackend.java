package com.github.unidbg.arm.backend;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.arm.Cpsr;
import com.github.unidbg.debugger.BreakPoint;
import com.github.unidbg.debugger.BreakPointCallback;
import com.github.unidbg.pointer.UnidbgPointer;
import unicorn.Arm64Const;
import unicorn.ArmConst;

import java.util.Collections;
import java.util.Map;

public abstract class AbstractBackend implements Backend {

    protected static class BreakPointImpl implements BreakPoint {
        final BreakPointCallback callback;
        final boolean thumb;
        boolean isTemporary;
        public BreakPointImpl(BreakPointCallback callback, boolean thumb) {
            this.callback = callback;
            this.thumb = thumb;
        }
        @Override
        public void setTemporary(boolean temporary) {
            this.isTemporary = true;
        }
        @Override
        public boolean isTemporary() {
            return isTemporary;
        }
        @Override
        public BreakPointCallback getCallback() {
            return callback;
        }
        @Override
        public boolean isThumb() {
            return thumb;
        }
    }

    protected void switchUserMode(boolean is64Bit) {
        if (!is64Bit) {
            Cpsr.getArm(this).switchUserMode();
        }
    }

    protected void enableVFP(boolean is64Bit) {
        if (is64Bit) {
            long value = reg_read(Arm64Const.UC_ARM64_REG_CPACR_EL1).longValue();
            value |= 0x300000; // set the FPEN bits
            reg_write(Arm64Const.UC_ARM64_REG_CPACR_EL1, value);
        } else {
            int value = reg_read(ArmConst.UC_ARM_REG_C1_C0_2).intValue();
            value |= (0xf << 20);
            reg_write(ArmConst.UC_ARM_REG_C1_C0_2, value);
            reg_write(ArmConst.UC_ARM_REG_FPEXC, 0x40000000);
        }
    }

    protected static void checkVectorRegId(int regId, boolean is64Bit) {
        if (is64Bit) {
            if (regId < Arm64Const.UC_ARM64_REG_Q0 || regId > Arm64Const.UC_ARM64_REG_Q31) {
                throw new UnsupportedOperationException("regId=" + regId);
            }
        } else {
            if (regId < ArmConst.UC_ARM_REG_D0 || regId > ArmConst.UC_ARM_REG_D15) {
                throw new UnsupportedOperationException("regId=" + regId);
            }
        }
    }

    protected static int decodeSWI(Emulator<?> emulator, Backend backend, boolean is64Bit) {
        if (is64Bit) {
            UnidbgPointer pc = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_PC);
            return (pc.getInt(-4) >> 5) & 0xffff;
        } else {
            UnidbgPointer pc = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_PC);
            boolean isThumb = ARM.isThumb(backend);
            if (isThumb) {
                return pc.getShort(-2) & 0xff;
            } else {
                return pc.getInt(-4) & 0xffffff;
            }
        }
    }

    @Override
    public void onInitialize() {
    }

    @Override
    public int getPageSize() {
        return 0;
    }

    @Override
    public void registerEmuCountHook(long emu_count) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void removeJitCodeCache(long begin, long end) throws BackendException {
    }

    @Override
    public Map<String, Integer> getCpuFeatures() {
        return Collections.emptyMap();
    }

    @Override
    public long getMemAllocatedSize() {
        throw new UnsupportedOperationException();
    }

    @Override
    public long getMemResidentSize() {
        throw new UnsupportedOperationException();
    }

}
