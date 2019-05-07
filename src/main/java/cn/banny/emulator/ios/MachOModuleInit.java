package cn.banny.emulator.ios;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.ios.struct.MachHeader;
import cn.banny.emulator.pointer.UnicornPointer;
import cn.banny.emulator.spi.InitFunction;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.ArrayList;
import java.util.List;

class MachOModuleInit extends InitFunction {

    private static final Log log = LogFactory.getLog(MachOModuleInit.class);

    private final MachOLoader loader;
    private final UnicornPointer envp;
    private final UnicornPointer apple;
    private final UnicornPointer vars;
    private final boolean isModInit;

    MachOModuleInit(MachOLoader loader, MachOModule module, UnicornPointer envp, UnicornPointer apple, UnicornPointer vars, boolean isModInit, long... addresses) {
        super(module.base, module.name, addresses);
        this.loader = loader;
        this.envp = envp;
        this.apple = apple;
        this.vars = vars;
        this.isModInit = isModInit;
    }

    /**
     * initializer(int argc, const char* argv[], const char* envp[], const char* apple[], const struct ProgramVars* vars)
     */
    public void call(Emulator emulator) {
//        emulator.traceCode();
        MachHeader header = null;
        if ("libSystem.B.dylib".equals(libName)) {
            MachOModule execute = loader.NSGetMachExecuteHeader();
            header = new MachHeader(UnicornPointer.pointer(emulator, execute.machHeader));
            if (log.isDebugEnabled()) {
                log.debug("setExecutable execute=" + execute + ", header=" + header);
            }
            if (!header.setExecutable()) {
                header = null;
            }
        }
        try {
            for (long addr : addresses) {
                if (isModInit) {
                    log.debug("[" + libName + "]CallInitFunction: 0x" + Long.toHexString(addr));
                } else {
                    log.debug("[" + libName + "]CallRoutineFunction: 0x" + Long.toHexString(addr));
                }
//            emulator.attach().addBreakPoint(null, 0x401d6be6);
//            emulator.attach().addBreakPoint(null, 0x402fb538);
                long start = System.currentTimeMillis();
                callModInit(emulator, load_base + addr, 0, null, envp, apple, vars);
                if (log.isDebugEnabled()) {
                    if (isModInit) {
                        System.err.println("[" + libName + "]CallInitFunction: 0x" + Long.toHexString(addr) + ", offset=" + (System.currentTimeMillis() - start) + "ms");
                    } else {
                        System.err.println("[" + libName + "]CallRoutineFunction: 0x" + Long.toHexString(addr) + ", offset=" + (System.currentTimeMillis() - start) + "ms");
                    }
                }
            }
        } finally {
            if (header != null) {
                header.resetFileType();
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
