package com.github.unidbg.arm.backend;

import unicorn.Unicorn;

public class UnicornBackend implements Backend {

    private final Unicorn unicorn;

    public UnicornBackend(Unicorn unicorn) {
        this.unicorn = unicorn;
    }

    @Override
    public Number reg_read(int regId) {
        return (Number) unicorn.reg_read(regId);
    }

    @SuppressWarnings("deprecation")
    @Override
    public byte[] reg_read(int regId, int regSize) {
        return unicorn.reg_read(regId, regSize);
    }

    @Override
    public void reg_write(int regId, Number value) {
        unicorn.reg_write(regId, value);
    }

    @Override
    public byte[] mem_read(long address, long size) {
        return unicorn.mem_read(address, size);
    }

    @Override
    public void mem_write(long address, byte[] bytes) {
        unicorn.mem_write(address, bytes);
    }

    @Override
    public void mem_map(long address, long size, int perms) {
        unicorn.mem_map(address, size, perms);
    }

    @Override
    public void mem_protect(long address, long size, int perms) {
        unicorn.mem_protect(address, size, perms);
    }

    @Override
    public void mem_unmap(long address, long size) {
        unicorn.mem_unmap(address, size);
    }

    @Override
    public void addBreakPoint(long address) {
        unicorn.addBreakPoint(address);
    }

    @Override
    public void removeBreakPoint(long address) {
        unicorn.removeBreakPoint(address);
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
    public Unicorn.UnHook hook_add_new(final CodeHook callback, long begin, long end, Object user_data) {
        return unicorn.hook_add_new(new unicorn.CodeHook() {
            @Override
            public void hook(Unicorn u, long address, int size, Object user) {
                callback.hook(UnicornBackend.this, address, size, user);
            }
        }, begin, end, user_data);
    }

    @Override
    public Unicorn.UnHook debugger_add(final DebugHook callback, long begin, long end, Object user_data) {
        return unicorn.debugger_add(new unicorn.DebugHook() {
            @Override
            public void onBreak(Unicorn u, long address, int size, Object user) {
                callback.onBreak(UnicornBackend.this, address, size, user);
            }
            @Override
            public void hook(Unicorn u, long address, int size, Object user) {
                callback.hook(UnicornBackend.this, address, size, user);
            }
        }, begin, end, user_data);
    }

    @Override
    public void hook_add_new(final ReadHook callback, long begin, long end, Object user_data) {
        unicorn.hook_add_new(new unicorn.ReadHook() {
            @Override
            public void hook(Unicorn u, long address, int size, Object user) {
                callback.hook(UnicornBackend.this, address, size, user);
            }
        }, begin, end, user_data);
    }

    @Override
    public void hook_add_new(final WriteHook callback, long begin, long end, Object user_data) {
        unicorn.hook_add_new(new unicorn.WriteHook() {
            @Override
            public void hook(Unicorn u, long address, int size, long value, Object user) {
                callback.hook(UnicornBackend.this, address, size, value, user);
            }
        }, begin, end, user_data);
    }

    @Override
    public void hook_add_new(final EventMemHook callback, int type, Object user_data) {
        unicorn.hook_add_new(new unicorn.EventMemHook() {
            @Override
            public boolean hook(Unicorn u, long address, int size, long value, Object user) {
                return callback.hook(UnicornBackend.this, address, size, value, user);
            }
        }, type, user_data);
    }

    @Override
    public void hook_add_new(final InterruptHook callback, Object user_data) {
        unicorn.hook_add_new(new unicorn.InterruptHook() {
            @Override
            public void hook(Unicorn u, int intno, Object user) {
                callback.hook(UnicornBackend.this, intno, user);
            }
        }, user_data);
    }

    @Override
    public Unicorn.UnHook hook_add_new(final BlockHook callback, long begin, long end, Object user_data) {
        return unicorn.hook_add_new(new unicorn.BlockHook() {
            @Override
            public void hook(Unicorn u, long address, int size, Object user) {
                callback.hook(UnicornBackend.this, address, size, user);
            }
        }, begin, end, user_data);
    }

    @Override
    public void emu_start(long begin, long until, long timeout, long count) {
        unicorn.emu_start(begin, until, timeout, count);
    }

    @Override
    public void emu_stop() {
        unicorn.emu_stop();
    }

    @Override
    public void destroy() {
        unicorn.closeAll();
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
}
