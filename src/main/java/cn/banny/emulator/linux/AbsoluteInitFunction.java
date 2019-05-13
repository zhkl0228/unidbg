package cn.banny.emulator.linux;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.pointer.UnicornPointer;
import cn.banny.emulator.spi.InitFunction;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class AbsoluteInitFunction extends InitFunction {

    private static final Log log = LogFactory.getLog(AbsoluteInitFunction.class);

    AbsoluteInitFunction(long load_base, String libName, long address) {
        super(load_base, libName, address);
    }

    @Override
    public long getAddress() {
        return address;
    }

    @Override
    public void call(Emulator emulator) {
        if (address == 0 || address == -1) {
            return;
        }

        Pointer pointer = UnicornPointer.pointer(emulator, address);
        log.debug("[" + libName + "]CallInitFunction: " + pointer);
        long start = System.currentTimeMillis();

        Log log = LogFactory.getLog("cn.banny.emulator.linux." + libName);
        if (log.isDebugEnabled()) {
            emulator.traceCode();
            emulator.eFunc(address);
        } else {
            emulator.eInit(address);
        }
        if (AbsoluteInitFunction.log.isDebugEnabled()) {
            System.err.println("[" + libName + "]CallInitFunction: " + pointer + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        }
    }

}
