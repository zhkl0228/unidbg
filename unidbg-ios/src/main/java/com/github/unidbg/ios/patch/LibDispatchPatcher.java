package com.github.unidbg.ios.patch;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.spi.ModulePatcher;
import com.sun.jna.Pointer;

public class LibDispatchPatcher extends ModulePatcher {

    public LibDispatchPatcher() {
        super("/usr/lib/system/libdispatch.dylib");
    }

    protected void patch32(Emulator<?> emulator, Module module) {
        Pointer pointer = UnidbgPointer.pointer(emulator, module.base + 0x211b4); // dispatch_semaphore_wait
        assert pointer != null;
        int code = pointer.getInt(0);
        if (code != 0xe59fc004) {
            throw new IllegalStateException("code=0x" + Integer.toHexString(code));
        }
        pointer.setInt(0, 0xe12fff1e); // bx lr
    }

    @Override
    protected void patch64(Emulator<?> emulator, Module module) {
        Pointer pointer = UnidbgPointer.pointer(emulator, module.base + 0xa830); // _dispatch_runloop_root_queue_perform_4CF
        assert pointer != null;
        int code = pointer.getInt(0);
        if (code != 0x91336129) {
            throw new IllegalStateException("code=0x" + Integer.toHexString(code));
        }
        pointer.setInt(0, 0xaa0803e9); // mov x9, x8
    }

}
