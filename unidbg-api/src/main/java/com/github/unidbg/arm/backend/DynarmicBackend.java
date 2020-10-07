package com.github.unidbg.arm.backend;

import unicorn.Unicorn;

public class DynarmicBackend implements Backend {

    @Override
    public void emu_start(long begin, long until, long timeout, long count) {
        throw new AbstractMethodError();
    }

    @Override
    public void emu_stop() {
        throw new AbstractMethodError();
    }

    @Override
    public void destroy() {
        throw new AbstractMethodError();
    }

    @Override
    public Number reg_read(int regId) {
        throw new AbstractMethodError();
    }

    @Override
    public void reg_write(int regId, Number value) {
        throw new AbstractMethodError();
    }

    @Override
    public byte[] mem_read(long address, long size) {
        throw new AbstractMethodError();
    }

    @Override
    public void mem_write(long address, byte[] bytes) {
        throw new AbstractMethodError();
    }

    @Override
    public void mem_map(long address, long size, int perms) {
        throw new AbstractMethodError();
    }

    @Override
    public void mem_protect(long address, long size, int perms) {
        throw new AbstractMethodError();
    }

    @Override
    public void mem_unmap(long address, long size) {
        throw new AbstractMethodError();
    }

    @Override
    public void hook_add_new(EventMemHook callback, int type, Object user_data) {
        throw new AbstractMethodError();
    }

    @Override
    public void hook_add_new(InterruptHook callback, Object user_data) {
        throw new AbstractMethodError();
    }

    @Override
    public void addBreakPoint(long address) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void removeBreakPoint(long address) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setSingleStep(int singleStep) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setFastDebug(boolean fastDebug) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Unicorn.UnHook hook_add_new(CodeHook callback, long begin, long end, Object user_data) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Unicorn.UnHook debugger_add(DebugHook callback, long begin, long end, Object user_data) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void hook_add_new(ReadHook callback, long begin, long end, Object user_data) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void hook_add_new(WriteHook callback, long begin, long end, Object user_data) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Unicorn.UnHook hook_add_new(BlockHook callback, long begin, long end, Object user_data) {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] reg_read(int regId, int regSize) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void context_restore(long context) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void context_save(long context) {
        throw new UnsupportedOperationException();
    }

    @Override
    public long context_alloc() {
        throw new UnsupportedOperationException();
    }

}
