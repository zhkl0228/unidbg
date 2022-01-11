package com.github.unidbg.arm.backend;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.arm.Cpsr;
import com.github.unidbg.arm.backend.unicorn.Unicorn;
import com.github.unidbg.debugger.BreakPoint;
import com.github.unidbg.debugger.BreakPointCallback;
import com.github.unidbg.pointer.UnidbgPointer;
import unicorn.Arm64Const;
import unicorn.ArmConst;
import unicorn.UnicornConst;
import unicorn.UnicornException;

import java.util.Map;

class Unicorn2Backend extends AbstractBackend implements Backend {

    private final Emulator<?> emulator;
    private final boolean is64Bit;
    private final Unicorn unicorn;

    Unicorn2Backend(Emulator<?> emulator, boolean is64Bit) throws BackendException {
        this.emulator = emulator;
        this.is64Bit = is64Bit;
        try {
            this.unicorn = new Unicorn(is64Bit ? UnicornConst.UC_ARCH_ARM64 : UnicornConst.UC_ARCH_ARM, UnicornConst.UC_MODE_ARM);
        } catch (UnicornException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void switchUserMode() {
        if (!is64Bit) {
            Cpsr.getArm(this).switchUserMode();
        }
    }

    @Override
    public void enableVFP() {
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

    @Override
    public byte[] reg_read_vector(int regId) throws BackendException {
        try {
            if (is64Bit) {
                if (regId < Arm64Const.UC_ARM64_REG_Q0 || regId > Arm64Const.UC_ARM64_REG_Q31) {
                    throw new UnsupportedOperationException("regId=" + regId);
                }
            } else {
                if (regId < ArmConst.UC_ARM_REG_D0 || regId > ArmConst.UC_ARM_REG_D15) {
                    throw new UnsupportedOperationException("regId=" + regId);
                }
            }
            return unicorn.reg_read(regId, 16);
        } catch (UnicornException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void reg_write_vector(int regId, byte[] vector) throws BackendException {
        if (vector.length != 16) {
            throw new IllegalStateException("Invalid vector size");
        }
        try {
            if (is64Bit) {
                if (regId < Arm64Const.UC_ARM64_REG_Q0 || regId > Arm64Const.UC_ARM64_REG_Q31) {
                    throw new UnsupportedOperationException("regId=" + regId);
                }
            } else {
                if (regId < ArmConst.UC_ARM_REG_D0 || regId > ArmConst.UC_ARM_REG_D15) {
                    throw new UnsupportedOperationException("regId=" + regId);
                }
            }
            unicorn.reg_write(regId, vector);
        } catch (UnicornException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public Number reg_read(int regId) throws BackendException {
        try {
            return unicorn.reg_read(regId);
        } catch (UnicornException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void reg_write(int regId, Number value) throws BackendException {
        try {
            unicorn.reg_write(regId, is64Bit ? value.longValue() : value.intValue());
        } catch (UnicornException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public byte[] mem_read(long address, long size) throws BackendException {
        try {
            return unicorn.mem_read(address, size);
        } catch (UnicornException e) {
            throw new BackendException("mem_read address=0x" + Long.toHexString(address) + ", size=" + size, e);
        }
    }

    @Override
    public void mem_write(long address, byte[] bytes) throws BackendException {
        try {
            unicorn.mem_write(address, bytes);
        } catch (UnicornException e) {
            throw new BackendException("mem_write address=0x" + Long.toHexString(address), e);
        }
    }

    @Override
    public void mem_map(long address, long size, int perms) throws BackendException {
        try {
            unicorn.mem_map(address, size, perms);
        } catch (UnicornException e) {
            throw new BackendException("mem_map address=0x" + Long.toHexString(address) + ", size=" + size + ", perms=0x" + Integer.toHexString(perms), e);
        }
    }

    @Override
    public void mem_protect(long address, long size, int perms) throws BackendException {
        try {
            unicorn.mem_protect(address, size, perms);
        } catch (UnicornException e) {
            throw new BackendException("mem_protect address=0x" + Long.toHexString(address) + ", size=" + size + ", perms=0x" + Integer.toHexString(perms), e);
        }
    }

    @Override
    public void mem_unmap(long address, long size) throws BackendException {
        try {
            unicorn.mem_unmap(address, size);
        } catch (UnicornException e) {
            throw new BackendException("mem_unmap address=0x" + Long.toHexString(address) + ", size=" + size, e);
        }
    }

    private static class BreakPointImpl implements BreakPoint {
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

    @Override
    public BreakPoint addBreakPoint(long address, BreakPointCallback callback, boolean thumb) {
        BreakPointImpl breakPoint = new BreakPointImpl(callback, thumb);
        unicorn.addBreakPoint(address);
        return breakPoint;
    }

    @Override
    public boolean removeBreakPoint(long address) {
        unicorn.removeBreakPoint(address);
        return true;
    }

    @Override
    public void setSingleStep(int singleStep) {
        unicorn.setSingleStep(singleStep);
    }

    @Override
    public void setFastDebug(boolean fastDebug) {
        unicorn.setFastDebug(fastDebug);
    }

    @Override
    public void hook_add_new(final CodeHook callback, long begin, long end, Object user_data) throws BackendException {
        try {
            final Unicorn.UnHook unHook = unicorn.hook_add_new(new com.github.unidbg.arm.backend.unicorn.CodeHook() {
                @Override
                public void hook(Unicorn u, long address, int size, Object user) {
                    callback.hook(Unicorn2Backend.this, address, size, user);
                }
            }, begin, end, user_data);
            callback.onAttach(new UnHook() {
                @Override
                public void unhook() {
                    unHook.unhook();
                }
            });
        } catch (UnicornException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void debugger_add(final DebugHook callback, long begin, long end, Object user_data) throws BackendException {
        try {
            final Unicorn.UnHook unHook = unicorn.debugger_add(new com.github.unidbg.arm.backend.unicorn.DebugHook() {
                @Override
                public void onBreak(Unicorn u, long address, int size, Object user) {
                    callback.onBreak(Unicorn2Backend.this, address, size, user);
                }

                @Override
                public void hook(Unicorn u, long address, int size, Object user) {
                    callback.hook(Unicorn2Backend.this, address, size, user);
                }
            }, begin, end, user_data);
            callback.onAttach(new UnHook() {
                @Override
                public void unhook() {
                    unHook.unhook();
                }
            });
        } catch (UnicornException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void hook_add_new(final ReadHook callback, long begin, long end, Object user_data) throws BackendException {
        try {
            final Unicorn.UnHook unHook = unicorn.hook_add_new(new com.github.unidbg.arm.backend.unicorn.ReadHook() {
                @Override
                public void hook(Unicorn u, long address, int size, Object user) {
                    callback.hook(Unicorn2Backend.this, address, size, user);
                }
            }, begin, end, user_data);
            callback.onAttach(new UnHook() {
                @Override
                public void unhook() {
                    unHook.unhook();
                }
            });
        } catch (UnicornException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void hook_add_new(final WriteHook callback, long begin, long end, Object user_data) throws BackendException {
        try {
            final Unicorn.UnHook unHook = unicorn.hook_add_new(new com.github.unidbg.arm.backend.unicorn.WriteHook() {
                @Override
                public void hook(Unicorn u, long address, int size, long value, Object user) {
                    callback.hook(Unicorn2Backend.this, address, size, value, user);
                }
            }, begin, end, user_data);
            callback.onAttach(new UnHook() {
                @Override
                public void unhook() {
                    unHook.unhook();
                }
            });
        } catch (UnicornException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void hook_add_new(final EventMemHook callback, final int type, Object user_data) throws BackendException {
        if ((type & UnicornConst.UC_HOOK_MEM_READ_UNMAPPED) != 0) {
            hookEventMem(callback, UnicornConst.UC_HOOK_MEM_READ_UNMAPPED, user_data, EventMemHook.UnmappedType.Read);
        }
        if ((type & UnicornConst.UC_HOOK_MEM_WRITE_UNMAPPED) != 0) {
            hookEventMem(callback, UnicornConst.UC_HOOK_MEM_WRITE_UNMAPPED, user_data, EventMemHook.UnmappedType.Write);
        }
        if ((type & UnicornConst.UC_HOOK_MEM_FETCH_UNMAPPED) != 0) {
            hookEventMem(callback, UnicornConst.UC_HOOK_MEM_FETCH_UNMAPPED, user_data, EventMemHook.UnmappedType.Fetch);
        }
    }

    private void hookEventMem(final EventMemHook callback, final int type, Object user_data, final EventMemHook.UnmappedType unmappedType) {
        try {
            Map<Integer, Unicorn.UnHook> map = unicorn.hook_add_new(new com.github.unidbg.arm.backend.unicorn.EventMemHook() {
                @Override
                public boolean hook(Unicorn u, long address, int size, long value, Object user) {
                    return callback.hook(Unicorn2Backend.this, address, size, value, user, unmappedType);
                }
            }, type, user_data);
            for (final Unicorn.UnHook unHook : map.values()) {
                callback.onAttach(new UnHook() {
                    @Override
                    public void unhook() {
                        unHook.unhook();
                    }
                });
            }
        } catch (UnicornException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void hook_add_new(final InterruptHook callback, Object user_data) throws BackendException {
        try {
            final Unicorn.UnHook unHook = unicorn.hook_add_new(new com.github.unidbg.arm.backend.unicorn.InterruptHook() {
                @Override
                public void hook(Unicorn u, int intno, Object user) {
                    int swi;
                    if (is64Bit) {
                        UnidbgPointer pc = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_PC);
                        swi = (pc.getInt(-4) >> 5) & 0xffff;
                    } else {
                        UnidbgPointer pc = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_PC);
                        boolean isThumb = ARM.isThumb(Unicorn2Backend.this);
                        if (isThumb) {
                            swi = pc.getShort(-2) & 0xff;
                        } else {
                            swi = pc.getInt(-4) & 0xffffff;
                        }
                    }
                    callback.hook(Unicorn2Backend.this, intno, swi, user);
                }
            }, user_data);
            callback.onAttach(new UnHook() {
                @Override
                public void unhook() {
                    unHook.unhook();
                }
            });
        } catch (UnicornException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void hook_add_new(final BlockHook callback, long begin, long end, Object user_data) throws BackendException {
        try {
            final Unicorn.UnHook unHook = unicorn.hook_add_new(new com.github.unidbg.arm.backend.unicorn.BlockHook() {
                @Override
                public void hook(Unicorn u, long address, int size, Object user) {
                    callback.hookBlock(Unicorn2Backend.this, address, size, user);
                }
            }, begin, end, user_data);
            callback.onAttach(new UnHook() {
                @Override
                public void unhook() {
                    unHook.unhook();
                }
            });
        } catch (UnicornException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public final synchronized void emu_start(long begin, long until, long timeout, long count) throws BackendException {
        try {
            unicorn.emu_start(begin, until, timeout, count);
        } catch (UnicornException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void emu_stop() throws BackendException {
        try {
            unicorn.emu_stop();
        } catch (UnicornException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void destroy() throws BackendException {
        try {
            unicorn.closeAll();
        } catch (UnicornException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void context_restore(long context) {
        unicorn.context_restore(context);
    }

    @Override
    public void context_save(long context) {
        unicorn.context_save(context);
    }

    @Override
    public long context_alloc() {
        return unicorn.context_alloc();
    }

    @Override
    public void context_free(long context) {
        Unicorn.free(context);
    }

    private Unicorn.UnHook unHook;

    @Override
    public void registerEmuCountHook(long emu_count) {
        if (unHook != null) {
            throw new IllegalStateException();
        }
        if (emu_count <= 0) {
            throw new IllegalArgumentException();
        } else {
            unHook = unicorn.registerEmuCountHook(emu_count);
        }
    }
}
