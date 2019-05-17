package cn.banny.unidbg.linux;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.pointer.UnicornPointer;
import cn.banny.unidbg.spi.InitFunction;
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

        emulator.eInit(address);
        if (AbsoluteInitFunction.log.isDebugEnabled()) {
            System.err.println("[" + libName + "]CallInitFunction: " + pointer + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        }
    }

}
