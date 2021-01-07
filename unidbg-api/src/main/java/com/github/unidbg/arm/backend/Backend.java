package com.github.unidbg.arm.backend;

import com.github.unidbg.debugger.BreakPoint;
import com.github.unidbg.debugger.BreakPointCallback;
import unicorn.Unicorn;

public interface Backend {

    void onInitialize();

    void switchUserMode();
    void enableVFP();

    Number reg_read(int regId)throws BackendException;

    byte[] reg_read_vector(int regId) throws BackendException;
    void reg_write_vector(int regId, byte[] vector) throws BackendException;

    void reg_write(int regId, Number value) throws BackendException;

    byte[] mem_read(long address, long size) throws BackendException;

    void mem_write(long address, byte[] bytes) throws BackendException;

    void mem_map(long address, long size, int perms) throws BackendException;

    void mem_protect(long address, long size, int perms) throws BackendException;

    void mem_unmap(long address, long size) throws BackendException;

    BreakPoint addBreakPoint(long address, BreakPointCallback callback, boolean thumb);
    boolean removeBreakPoint(long address);
    void setSingleStep(int singleStep);
    void setFastDebug(boolean fastDebug);

    Unicorn.UnHook hook_add_new(CodeHook callback, long begin, long end, Object user_data) throws BackendException;

    Unicorn.UnHook debugger_add(DebugHook callback, long begin, long end, Object user_data) throws BackendException;

    void hook_add_new(ReadHook callback, long begin, long end, Object user_data) throws BackendException;

    void hook_add_new(WriteHook callback, long begin, long end, Object user_data) throws BackendException;

    void hook_add_new(EventMemHook callback, int type, Object user_data) throws BackendException;

    void hook_add_new(InterruptHook callback, Object user_data) throws BackendException;

    @SuppressWarnings("unused")
    Unicorn.UnHook hook_add_new(BlockHook callback, long begin, long end, Object user_data) throws BackendException;

    void emu_start(long begin, long until, long timeout, long count) throws BackendException;

    void emu_stop() throws BackendException;

    void destroy() throws BackendException;

    void context_restore(long context);
    void context_save(long context);
    long context_alloc();

    int getPageSize();

}
