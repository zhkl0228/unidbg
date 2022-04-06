package com.github.unidbg.linux;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.spi.InitFunction;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

class AbsoluteInitFunction extends InitFunction {

    private static final Log log = LogFactory.getLog(AbsoluteInitFunction.class);

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
                log.debug("[" + libName + "]CallInitFunction: address=0x" + Long.toHexString(address) + ", ptr=" + ptr + ", func=" + ptr.getPointer(0));
            }
            return address;
        }

        Pointer pointer = UnidbgPointer.pointer(emulator, address);
        if (log.isDebugEnabled()) {
            log.debug("[" + libName + "]CallInitFunction: " + pointer);
        }
        long start = System.currentTimeMillis();

        emulator.eFunc(address);
        if (AbsoluteInitFunction.log.isDebugEnabled()) {
            System.err.println("[" + libName + "]CallInitFunction: " + pointer + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        }
        return address;
    }

}
