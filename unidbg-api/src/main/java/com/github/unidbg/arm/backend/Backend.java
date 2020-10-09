package com.github.unidbg.arm.backend;

import unicorn.Unicorn;

public interface Backend {

    void switchUserMode();
    void enableVFP();

    Number reg_read(int regId);

    byte[] reg_read(int regId, int regSize);

    void reg_write(int regId, Number value);

    byte[] mem_read(long address, long size);

    void mem_write(long address, byte[] bytes);

    void mem_map(long address, long size, int perms);

    void mem_protect(long address, long size, int perms);

    void mem_unmap(long address, long size);

    void addBreakPoint(long address);
    void removeBreakPoint(long address);
    void setSingleStep(int singleStep);
    void setFastDebug(boolean fastDebug);

    Unicorn.UnHook hook_add_new(CodeHook callback, long begin, long end, Object user_data);

    Unicorn.UnHook debugger_add(DebugHook callback, long begin, long end, Object user_data);

    void hook_add_new(ReadHook callback, long begin, long end, Object user_data);

    void hook_add_new(WriteHook callback, long begin, long end, Object user_data);

    void hook_add_new(EventMemHook callback, int type, Object user_data);

    void hook_add_new(InterruptHook callback, Object user_data);

    Unicorn.UnHook hook_add_new(BlockHook callback, long begin, long end, Object user_data);

    void emu_start(long begin, long until, long timeout, long count);

    void emu_stop();

    void destroy();

    void context_restore(long context);
    void context_save(long context);
    long context_alloc();

}
