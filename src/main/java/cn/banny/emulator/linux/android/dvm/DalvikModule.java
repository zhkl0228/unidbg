package cn.banny.emulator.linux.android.dvm;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.linux.Module;
import net.fornwall.jelf.ElfSymbol;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;

public class DalvikModule {

    private static final Log log = LogFactory.getLog(DalvikModule.class);

    private final BaseVM vm;
    private final Module module;

    DalvikModule(BaseVM vm, Module module) {
        this.vm = vm;
        this.module = module;
    }

    public Module getModule() {
        return module;
    }

    public void callJNI_OnLoad(Emulator emulator) throws IOException {
        ElfSymbol onLoad = module.getELFSymbolByName("JNI_OnLoad");
        if (onLoad != null) {
            long start = System.currentTimeMillis();
            log.debug("Call [" + module.name + "]JNI_OnLoad: 0x" + Long.toHexString(onLoad.value));
            module.callFunction(emulator, onLoad.value, vm.getJavaVM(), null);
            log.debug("Call [" + module.name + "]JNI_OnLoad finished, offset=" + (System.currentTimeMillis() - start) + "ms");
            vm.deleteLocalRefs();
        }
    }

}
