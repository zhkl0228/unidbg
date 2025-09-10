package com.github.unidbg.arm.backend;

import com.github.unidbg.debugger.BreakPoint;
import com.github.unidbg.debugger.BreakPointCallback;

import java.util.Map;

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

    void removeJitCodeCache(long begin, long end) throws BackendException;

    void hook_add_new(CodeHook callback, long begin, long end, Object user_data) throws BackendException;

    void debugger_add(DebugHook callback, long begin, long end, Object user_data) throws BackendException;

    void hook_add_new(ReadHook callback, long begin, long end, Object user_data) throws BackendException;

    void hook_add_new(WriteHook callback, long begin, long end, Object user_data) throws BackendException;

    void hook_add_new(EventMemHook callback, int type, Object user_data) throws BackendException;

    void hook_add_new(InterruptHook callback, Object user_data) throws BackendException;

    void hook_add_new(BlockHook callback, long begin, long end, Object user_data) throws BackendException;

    void emu_start(long begin, long until, long timeout, long count) throws BackendException;

    void emu_stop() throws BackendException;

    void destroy() throws BackendException;

    void context_restore(long context);
    void context_save(long context);
    long context_alloc();
    void context_free(long context);

    int getPageSize();

    void registerEmuCountHook(long emu_count);

    /**
     * <a href="https://github.com/google/cpu_features/blob/main/src/impl_aarch64_macos_or_iphone.c">arm64_features</a>
     * hw.optional.floatingpoint
     * hw.optional.AdvSIMD
     * hw.optional.arm.AdvSIMD
     * hw.optional.arm.FEAT_AES
     * hw.optional.arm.FEAT_PMULL
     * hw.optional.arm.FEAT_SHA1
     * hw.optional.arm.FEAT_SHA256
     * hw.optional.armv8_crc32
     * hw.optional.arm.FEAT_LSE
     * hw.optional.arm.FEAT_FP16
     * hw.optional.arm.AdvSIMD_HPFPCvt
     * hw.optional.arm.FEAT_RDM
     * hw.optional.arm.FEAT_JSCVT
     * hw.optional.arm.FEAT_FCMA
     * hw.optional.arm.FEAT_LRCPC
     * hw.optional.arm.FEAT_DPB
     * hw.optional.arm.FEAT_SHA3
     * hw.optional.arm.FEAT_DotProd
     * hw.optional.arm.FEAT_SHA512
     * hw.optional.arm.FEAT_FHM
     * hw.optional.arm.FEAT_DIT
     * hw.optional.arm.FEAT_LSE2
     * hw.optional.arm.FEAT_FlagM
     * hw.optional.arm.FEAT_SSBS
     * hw.optional.arm.FEAT_SB
     * hw.optional.arm.FEAT_FlagM2
     * hw.optional.arm.FEAT_FRINTTS
     * hw.optional.arm.FEAT_I8MM
     * hw.optional.arm.FEAT_BF16
     * hw.optional.arm.FEAT_BTI
     */
    Map<String, Integer> getCpuFeatures();

}
