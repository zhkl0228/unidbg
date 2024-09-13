package com.github.unidbg.linux;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.spi.InitFunction;
import com.sun.jna.Pointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class AbsoluteInitFunction extends InitFunction {

    private static final Logger log = LoggerFactory.getLogger(AbsoluteInitFunction.class);

    private final UnidbgPointer ptr;

    private static long getFuncAddress(UnidbgPointer ptr) {
        UnidbgPointer func = ptr.getPointer(0);
        return func == null ? 0 : func.peer;
    }

    AbsoluteInitFunction(long load_base, String libName, UnidbgPointer ptr) {
        super(load_base, libName, getFuncAddress(ptr));
        this.ptr = ptr;
    }

    @Override
    public long getAddress() {
        return address;
    }

    @Override
    public long call(Emulator<?> emulator) {
        long address = getFuncAddress(ptr);
        if (address == 0) {
            address = this.address;
        }

        if (emulator.is32Bit()) {
            address = (int) address;
        }

        if (address == 0 || address == -1) {
            if (log.isDebugEnabled()) {
                log.debug("[{}]CallInitFunction: address=0x{}, ptr={}, func={}", libName, Long.toHexString(address), ptr, ptr.getPointer(0));
            }
            return address;
        }

        Pointer pointer = UnidbgPointer.pointer(emulator, address);
        log.debug("[{}]CallInitFunction: {}", libName, pointer);
        long start = System.currentTimeMillis();

        emulator.eFunc(address);
        if (AbsoluteInitFunction.log.isDebugEnabled()) {
            System.err.println("[" + libName + "]CallInitFunction: " + pointer + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        }
        return address;
    }

}
