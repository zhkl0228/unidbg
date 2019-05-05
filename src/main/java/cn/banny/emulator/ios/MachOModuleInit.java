package cn.banny.emulator.ios;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.pointer.UnicornPointer;
import cn.banny.emulator.spi.InitFunction;
import com.sun.jna.Pointer;
import io.kaitai.MachO;
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

    MachOModuleInit(MachOLoader loader, MachOModule module, UnicornPointer envp, UnicornPointer apple, UnicornPointer vars, long... addresses) {
        super(module.base, module.name, addresses);
        this.loader = loader;
        this.envp = envp;
        this.apple = apple;
        this.vars = vars;
    }

    /**
     * initializer(int argc, const char* argv[], const char* envp[], const char* apple[], const struct ProgramVars* vars)
     */
    public void call(Emulator emulator) {
//        emulator.traceCode();
        Pointer header = null;
        int backupFileType = (int) MachO.FileType.DYLIB.id();
        if ("libSystem.B.dylib".equals(libName)) {
            header = UnicornPointer.pointer(emulator, loader.NSGetMachExecuteHeader().base);
            if (header != null) {
                backupFileType = header.getInt(0xc);
                if (backupFileType == MachO.FileType.EXECUTE.id()) {
                    header = null;
                } else {
                    header.setInt(0xc, (int) MachO.FileType.EXECUTE.id()); // mock execute file
                }
            }
        }
        try {
            for (long addr : addresses) {
                log.debug("[" + libName + "]CallInitFunction: 0x" + Long.toHexString(addr));
//            emulator.attach().addBreakPoint(null, 0x401d6be6);
//            emulator.attach().addBreakPoint(null, 0x402fb538);
                long start = System.currentTimeMillis();
                callModInit(emulator, load_base + addr, 0, null, envp, apple, vars);
                if (log.isDebugEnabled()) {
                    System.err.println("[" + libName + "]CallInitFunction: 0x" + Long.toHexString(addr) + ", offset=" + (System.currentTimeMillis() - start) + "ms");
                }
            }
        } finally {
            if (header != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Restore backupFileType=" + backupFileType + ", oldType=" + header.getInt(0xc));
                }
                header.setInt(0xc, backupFileType);
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
