package cn.banny.emulator.linux;

import cn.banny.emulator.Emulator;
import net.fornwall.jelf.ElfInitArray;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class InitFunction {

    private static final Log log = LogFactory.getLog(InitFunction.class);

    private final long load_base;
    private final String soName;
    public final long[] addresses;

    InitFunction(long load_base, String soName, ElfInitArray initArray) {
        this(load_base, soName, initArray.array);
    }

    InitFunction(long load_base, String soName, long...addresses) {
        this.load_base = load_base;
        this.soName = soName;
        this.addresses = addresses;
    }

    void call(Emulator emulator) {
        for (long addr : addresses) {
            if (addr == 0) {
                continue;
            }
            if (addr == -1) {
                continue;
            }

            log.debug("[" + soName + "]CallInitFunction: 0x" + Long.toHexString(addr));
            // emulator.traceCode();
            // emulator.traceWrite();
            long start = System.currentTimeMillis();
            emulator.eInit(load_base + addr);
            if (log.isDebugEnabled()) {
                System.err.println("[" + soName + "]CallInitFunction: 0x" + Long.toHexString(addr) + ", offset=" + (System.currentTimeMillis() - start) + "ms");
            }
        }
    }

}
