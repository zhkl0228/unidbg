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
            try {
                long start = System.currentTimeMillis();
                if (log.isDebugEnabled()) {
                    log.debug("Call [" + module.name + "]JNI_OnLoad: 0x" + Long.toHexString(onLoad.getAddress()));
                }
                Number ret = onLoad.call(emulator, vm.getJavaVM(), null);
                int version = ret.intValue();
                if (log.isDebugEnabled()) {
                    log.debug("Call [" + module.name + "]JNI_OnLoad finished: version=0x" + Integer.toHexString(version) + ", offset=" + (System.currentTimeMillis() - start) + "ms");
                }

                vm.checkVersion(version);
            } finally {
                vm.deleteLocalRefs();
            }
        }
    }

}
