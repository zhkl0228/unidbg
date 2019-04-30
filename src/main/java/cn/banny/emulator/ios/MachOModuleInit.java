package cn.banny.emulator.ios;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.pointer.UnicornPointer;
import cn.banny.emulator.spi.InitFunction;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.ArrayList;
import java.util.List;

class MachOModuleInit extends InitFunction {

    private static final Log log = LogFactory.getLog(MachOModuleInit.class);

    private final UnicornPointer envp;
    private final UnicornPointer apple;
    private final UnicornPointer vars;

    MachOModuleInit(long load_base, String libName, UnicornPointer envp, UnicornPointer apple, UnicornPointer vars, long... addresses) {
        super(load_base, libName, addresses);
        this.envp = envp;
        this.apple = apple;
        this.vars = vars;
    }

    /**
     * initializer(int argc, const char* argv[], const char* envp[], const char* apple[], const struct ProgramVars* vars)
     */
    public void call(Emulator emulator) {
        for (long addr : addresses) {
            log.debug("[" + libName + "]CallInitFunction: 0x" + Long.toHexString(addr));
//          emulator.attach().addBreakPoint(null, 0x402979aa);
//          emulator.attach().addBreakPoint(null, 0x4030116c);
            emulator.traceCode();
            long start = System.currentTimeMillis();
            callModInit(emulator, load_base + addr, 0, null, envp, apple, vars);
            if (log.isDebugEnabled()) {
                System.err.println("[" + libName + "]CallInitFunction: 0x" + Long.toHexString(addr) + ", offset=" + (System.currentTimeMillis() - start) + "ms");
            }
        }
    }

    // (int argc, const char* argv[], const char* envp[], const char* apple[], const struct ProgramVars* vars)
    private static void callModInit(Emulator emulator, long address, int argc, UnicornPointer argv, UnicornPointer envp, UnicornPointer apple, UnicornPointer vars) {
        List<Number> list = new ArrayList<>(5);
        list.add(argc);
        list.add(argv == null ? 0 : argv.peer);
        list.add(envp == null ? 0 : envp.peer);
        list.add(apple == null ? 0 : apple.peer);
        list.add(vars == null ? 0 : vars.peer);
        emulator.eFunc(address, list.toArray(new Number[0]));
    }

}
