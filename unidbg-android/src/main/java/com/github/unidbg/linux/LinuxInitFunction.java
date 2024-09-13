package com.github.unidbg.linux;

import com.github.unidbg.Emulator;
import com.github.unidbg.spi.InitFunction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class LinuxInitFunction extends InitFunction {

    private static final Logger log = LoggerFactory.getLogger(LinuxInitFunction.class);

    LinuxInitFunction(long load_base, String soName, long address) {
        super(load_base, soName, address);
    }

    @Override
    public long getAddress() {
        return load_base + address;
    }

    @Override
    public long call(Emulator<?> emulator) {
        if (address == 0 || address == -1) {
            return address;
        }

        if (log.isDebugEnabled()) {
            log.debug("[{}]CallInitFunction: 0x{}", libName, Long.toHexString(address));
        }
        long start = System.currentTimeMillis();
        emulator.eFunc(getAddress());
        if (log.isDebugEnabled()) {
            System.err.println("[" + libName + "]CallInitFunction: 0x" + Long.toHexString(address) + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        }
        return address;
    }

}
