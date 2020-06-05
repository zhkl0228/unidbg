package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

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

    public void callJNI_OnLoad(Emulator<?> emulator) {
        Symbol onLoad = module.findSymbolByName("JNI_OnLoad", false);
        if (onLoad != null) {
            long start = System.currentTimeMillis();
            log.debug("Call [" + module.name + "]JNI_OnLoad: 0x" + Long.toHexString(onLoad.getAddress()));
            onLoad.call(emulator, vm.getJavaVM(), null);
            log.debug("Call [" + module.name + "]JNI_OnLoad finished, offset=" + (System.currentTimeMillis() - start) + "ms");
            vm.deleteLocalRefs();
        }
    }

}
