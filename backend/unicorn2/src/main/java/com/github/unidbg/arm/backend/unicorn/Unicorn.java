package com.github.unidbg.arm.backend.unicorn;

import com.github.unidbg.thread.ThreadContextSwitchException;
import unicorn.UnicornConst;
import unicorn.UnicornException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;

public class Unicorn {

    private static final Hashtable<Integer,Integer> eventMemMap = new Hashtable<>();

    static {
        eventMemMap.put(UnicornConst.UC_HOOK_MEM_READ_UNMAPPED, UnicornConst.UC_MEM_READ_UNMAPPED);
        eventMemMap.put(UnicornConst.UC_HOOK_MEM_WRITE_UNMAPPED, UnicornConst.UC_MEM_WRITE_UNMAPPED);
        eventMemMap.put(UnicornConst.UC_HOOK_MEM_FETCH_UNMAPPED, UnicornConst.UC_MEM_FETCH_UNMAPPED);
        eventMemMap.put(UnicornConst.UC_HOOK_MEM_READ_PROT, UnicornConst.UC_MEM_READ_PROT);
        eventMemMap.put(UnicornConst.UC_HOOK_MEM_WRITE_PROT, UnicornConst.UC_MEM_WRITE_PROT);
        eventMemMap.put(UnicornConst.UC_HOOK_MEM_FETCH_PROT, UnicornConst.UC_MEM_FETCH_PROT);
        eventMemMap.put(UnicornConst.UC_HOOK_MEM_READ, UnicornConst.UC_MEM_READ);
        eventMemMap.put(UnicornConst.UC_HOOK_MEM_WRITE, UnicornConst.UC_MEM_WRITE);
        eventMemMap.put(UnicornConst.UC_HOOK_MEM_FETCH, UnicornConst.UC_MEM_FETCH);
        eventMemMap.put(UnicornConst.UC_HOOK_MEM_READ_AFTER, UnicornConst.UC_MEM_READ_AFTER);
    }

    private static class Tuple {
        public Hook function;
        public Object data;
        public Tuple(Hook f, Object d) {
            function = f;
            data = d;
        }
    }

    public class UnHook {
        private final long handle;
        public UnHook(long handle) {
            this.handle = handle;
            newHookList.add(this);
        }
        public void unhook() {
            unhookInternal();
            newHookList.remove(this);
        }
        private boolean unhooked;
        private void unhookInternal() {
            if (!unhooked && handle != 0) {
                hook_del(handle);
            }
            unhooked = true;
        }
    }

    private class NewHook extends Tuple {

        public NewHook(Hook f, Object d) {
            super(f, d);
        }

        /**
         * for UC_HOOK_BLOCK
         */
        void onBlock(long address, int size) {
            BlockHook hook = (BlockHook) function;
            hook.hook(Unicorn.this, address, size, data);
        }

        /**
         * for UC_HOOK_CODE
         */
        void onCode(long address, int size) {
            CodeHook hook = (CodeHook) function;
            hook.hook(Unicorn.this, address, size, data);
        }

        /**
         * on breakpoint hit
         */
        void onBreak(long address, int size) {
            DebugHook hook = (DebugHook) function;
            hook.onBreak(Unicorn.this, address, size, data);
        }

        /**
         * for UC_HOOK_MEM_READ
         */
        void onRead(long address, int size) {
            ReadHook hook = (ReadHook) function;
            hook.hook(Unicorn.this, address, size, data);
        }

        /**
         * for UC_HOOK_MEM_WRITE
         */
        void onWrite(long address, int size, long value) {
            WriteHook hook = (WriteHook) function;
            hook.hook(Unicorn.this, address, size, value, data);
        }

        /**
         * for UC_HOOK_INTR
         */
        void onInterrupt(int intno) {
            InterruptHook hook = (InterruptHook) function;
            hook.hook(Unicorn.this, intno, data);
        }

        /**
         * for UC_HOOK_MEM_*
         */
        boolean onMemEvent(int type, long address, int size, long value) {
            EventMemHook hook = (EventMemHook) function;
            return hook.hook(Unicorn.this, address, size, value, data);
        }
    }

    /**
     * Native access to uc_open
     *
     * @param  arch  Architecture type (UC_ARCH_*)
     * @param  mode  Hardware mode. This is combined of UC_MODE_*
     */
    private static native long nativeInitialize(int arch, int mode) throws UnicornException;

    /**
     * Close the underlying uc_engine* eng associated with this Unicorn object
     *
     */
    private static native void nativeDestroy(long handle) throws UnicornException;

    /**
     * Hook registration helper for unhook.
     *
     * @param handle   Unicorn uch returned for registered hook function
     */
    private static native void hook_del(long handle) throws UnicornException;

    /**
     * Read register value.
     *
     * @param regid  Register ID that is to be retrieved.
     * @param regsz  Size of the register being retrieved.
     * @return Byte array containing the requested register value.
     */
    public byte[] reg_read(int regid, int regsz) throws UnicornException {
        return reg_read(nativeHandle, regid, regsz);
    }

    private static native byte[] reg_read(long handle, int regid, int regsz) throws UnicornException;

    /**
     * Write to register.
     *
     * @param  regid  Register ID that is to be modified.
     * @param  value  Array containing value that will be written into register @regid
     */
    public void reg_write(int regid, byte[] value) throws UnicornException {
        reg_write(nativeHandle, regid, value);
    }

    private static native void reg_write(long handle, int regid, byte[] value) throws UnicornException;

    /**
     * Read register value.
     *
     * @param regid  Register ID that is to be retrieved.
     * @return Number containing the requested register value.
     */
    public long reg_read(int regid) throws UnicornException {
        return reg_read(nativeHandle, regid);
    }

    private static native long reg_read(long handle, int regid) throws UnicornException;

    /**
     * Write to register.
     *
     * @param  regid  Register ID that is to be modified.
     * @param  value  Number containing the new register value
     */
    public void reg_write(int regid, long value) throws UnicornException {
        reg_write(nativeHandle, regid, value);
    }

    private static native void reg_write(long handle, int regid, long value) throws UnicornException;

    public UnHook registerEmuCountHook(long emu_count) {
        NewHook hook = new NewHook(new CodeHook() {
            @Override
            public void hook(Unicorn u, long address, int size, Object user) {
                throw new ThreadContextSwitchException();
            }
        }, null);
        return new UnHook(register_emu_count_hook(nativeHandle, emu_count, hook));
    }

    private static native long register_emu_count_hook(long handle, long emu_count, NewHook hook);

    /**
     * Read memory contents.
     *
     * @param address  Start addres of the memory region to be read.
     * @param size     Number of bytes to be retrieved.
     * @return Byte array containing the contents of the requested memory range.
     */
    public byte[] mem_read(long address, long size) throws UnicornException {
        return mem_read(nativeHandle, address, size);
    }

    private static native byte[] mem_read(long handle, long address, long size) throws UnicornException;

    /**
     * Write to memory.
     *
     * @param  address  Start addres of the memory region to be written.
     * @param  bytes    The values to be written into memory. bytes.length bytes will be written.
     */
    public void mem_write(long address, byte[] bytes) throws UnicornException {
        mem_write(nativeHandle, address, bytes);
    }

    private static native void mem_write(long handle, long address, byte[] bytes) throws UnicornException;

    /**
     * Map a range of memory.
     *
     * @param address Base address of the memory range
     * @param size    Size of the memory block.
     * @param perms   Permissions on the memory block. A combination of UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
     */
    public void mem_map(long address, long size, int perms) throws UnicornException {
        mem_map(nativeHandle, address, size, perms);
    }

    private static native void mem_map(long handle, long address, long size, int perms) throws UnicornException;

    /**
     * Change permissions on a range of memory.
     *
     * @param address Base address of the memory range
     * @param size    Size of the memory block.
     * @param perms   New permissions on the memory block. A combination of UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
     */
    public void mem_protect(long address, long size, int perms) throws UnicornException {
        mem_protect(nativeHandle, address, size, perms);
    }

    private static native void mem_protect(long handle, long address, long size, int perms) throws UnicornException;

    /**
     * Unmap a range of memory.
     *
     * @param address Base address of the memory range
     * @param size    Size of the memory block.
     */
    public void mem_unmap(long address, long size) throws UnicornException {
        mem_unmap(nativeHandle, address, size);
    }

    private static native void mem_unmap(long handle, long address, long size) throws UnicornException;

    public void setFastDebug(boolean fastDebug) {
        setFastDebug(nativeHandle, fastDebug);
    }
    private static native void setFastDebug(long handle, boolean fastDebug);
    public void setSingleStep(int singleStep) {
        setSingleStep(nativeHandle, singleStep);
    }
    private static native void setSingleStep(long handle, int singleStep);
    public void addBreakPoint(long address) {
        addBreakPoint(nativeHandle, address);
    }
    private static native void addBreakPoint(long handle, long address);
    public void removeBreakPoint(long address) {
        removeBreakPoint(nativeHandle, address);
    }
    private static native void removeBreakPoint(long handle, long address);

    /**
     * Hook registration helper for hook types that require two additional arguments.
     *
     * @param handle   Internal unicorn uc_engine* eng associated with hooking Unicorn object
     * @param type     UC_HOOK_* hook type
     * @return         Unicorn uch returned for registered hook function
     */
    private native static long registerHook(long handle, int type, long begin, long end, NewHook hook);

    /**
     * Hook registration helper for hook types that require no additional arguments.
     *
     * @param handle   Internal unicorn uc_engine* eng associated with hooking Unicorn object
     * @param type     UC_HOOK_* hook type
     * @return         Unicorn uch returned for registered hook function
     */
    private native static long registerHook(long handle, int type, NewHook hook);

    private native static long registerDebugger(long handle, long begin, long end, NewHook hook);

    /**
     * Emulate machine code in a specific duration of time.
     *
     * @param begin    Address where emulation starts
     * @param until    Address where emulation stops (i.e when this address is hit)
     * @param timeout  Duration to emulate the code (in microseconds). When this value is 0, we will emulate the code in infinite time, until the code is finished.
     * @param count    The number of instructions to be emulated. When this value is 0, we will emulate all the code available, until the code is finished.
     */
    public void emu_start(long begin, long until, long timeout, long count) throws UnicornException {
        emu_start(nativeHandle, begin, until, timeout, count);
    }

    private static native void emu_start(long handle, long begin, long until, long timeout, long count) throws UnicornException;

    /**
     * Stop emulation (which was started by emu_start() ).
     * This is typically called from callback functions registered via tracing APIs.
     * NOTE: for now, this will stop the execution only after the current block.
     */
    public void emu_stop() throws UnicornException {
        emu_stop(nativeHandle);
    }

    private static native void emu_stop(long handle) throws UnicornException;

    /**
     * Allocate a region that can be used with uc_context_{save,restore} to perform
     * quick save/rollback of the CPU context, which includes registers and some
     * internal metadata. Contexts may not be shared across engine instances with
     * differing arches or modes.
     *
     * @return context handle for use with save/restore.
     */
    public long context_alloc() {
        return context_alloc(nativeHandle);
    }

    private static native long context_alloc(long handle);

    /**
     * Free a resource allocated within Unicorn. Use for handles
     * allocated by context_alloc.
     *
     * @param handle Previously allocated Unicorn object handle.
     */
    public static native void free(long handle);

    /**
     * Save a copy of the internal CPU context.
     * This API should be used to efficiently make or update a saved copy of the
     * internal CPU state.
     *
     * @param context handle previously returned by context_alloc.
     */
    public void context_save(long context) {
        context_save(nativeHandle, context);
    }

    private static native void context_save(long handle, long context);

    /**
     * Restore the current CPU context from a saved copy.
     * This API should be used to roll the CPU context back to a previous
     * state saved by uc_context_save().
     *
     * @param context handle previously returned by context_alloc.
     */
    public void context_restore(long context) {
        context_restore(nativeHandle, context);
    }

    private static native void context_restore(long handle, long context);

    public static native void testSampleArm();
    public static native void testSampleArm64();

    public UnHook hook_add_new(BlockHook callback, long begin, long end, Object user_data) throws UnicornException {
        NewHook hook = new NewHook(callback, user_data);
        long handle = registerHook(nativeHandle, UnicornConst.UC_HOOK_BLOCK, begin, end, hook);
        return new UnHook(handle);
    }

    public UnHook hook_add_new(InterruptHook callback, Object user_data) throws UnicornException {
        NewHook hook = new NewHook(callback, user_data);
        long handle = registerHook(nativeHandle, UnicornConst.UC_HOOK_INTR, hook);
        return new UnHook(handle);
    }

    public Map<Integer, UnHook> hook_add_new(EventMemHook callback, int type, Object user_data) throws UnicornException {
        //test all of the EventMem related bits in type
        Map<Integer, UnHook> map = new HashMap<>(eventMemMap.size());
        for (Integer htype : eventMemMap.keySet()) {
            if ((type & htype) != 0) { //the 'htype' bit is set in type
                NewHook hook = new NewHook(callback, user_data);
                long handle = registerHook(nativeHandle, htype, hook);
                map.put(htype, new UnHook(handle));
            }
        }
        return map;
    }

    public UnHook hook_add_new(ReadHook callback, long begin, long end, Object user_data) throws UnicornException {
        NewHook hook = new NewHook(callback, user_data);
        long handle = registerHook(nativeHandle, UnicornConst.UC_HOOK_MEM_READ, begin, end, hook);
        return new UnHook(handle);
    }

    public UnHook hook_add_new(WriteHook callback, long begin, long end, Object user_data) throws UnicornException {
        NewHook hook = new NewHook(callback, user_data);
        long handle = registerHook(nativeHandle, UnicornConst.UC_HOOK_MEM_WRITE, begin, end, hook);
        return new UnHook(handle);
    }

    public UnHook hook_add_new(CodeHook callback, long begin, long end, Object user_data) throws UnicornException {
        NewHook hook = new NewHook(callback, user_data);
        long handle = registerHook(nativeHandle, UnicornConst.UC_HOOK_CODE, begin, end, hook);
        return new UnHook(handle);
    }

    public UnHook debugger_add(DebugHook callback, long begin, long end, Object user_data) throws UnicornException {
        NewHook hook = new NewHook(callback, user_data);
        long handle = registerDebugger(nativeHandle, begin, end, hook);
        return new UnHook(handle);
    }

    private final List<UnHook> newHookList = new ArrayList<>();
    private final long nativeHandle;

    public Unicorn(int arch, int mode) throws UnicornException {
        this.nativeHandle = nativeInitialize(arch, mode);
    }

    public void closeAll() throws UnicornException {
        for (UnHook unHook : newHookList) {
            unHook.unhookInternal();
        }
        nativeDestroy(nativeHandle);
    }

}
