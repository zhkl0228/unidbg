package cn.banny.emulator.ios;

import cn.banny.emulator.Dlfcn;
import cn.banny.emulator.Emulator;
import cn.banny.emulator.Module;
import cn.banny.emulator.arm.ArmSvc;
import cn.banny.emulator.memory.SvcMemory;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.ArmConst;

public class Dyld implements Dlfcn {

    private static final Log log = LogFactory.getLog(Dyld.class);

    private final MachOLoader loader;

    public Dyld(MachOLoader loader) {
        this.loader = loader;
    }

    @Override
    public long hook(SvcMemory svcMemory, String libraryName, String symbolName, long old) {
        if ("libdyld.dylib".equals(libraryName)) {
            if (log.isDebugEnabled()) {
                log.debug("hook symbolName=" + symbolName + ", old=0x" + Long.toHexString(old) + ", libraryName=" + libraryName);
            }
            if ("__dyld_image_count".equals(symbolName)) {
                return svcMemory.registerSvc(new ArmSvc() {
                    @Override
                    public int handle(Emulator emulator) {
                        return loader.getLoadedModules().size();
                    }
                }).peer;
            }
            if ("__dyld_get_image_name".equals(symbolName)) {
                return svcMemory.registerSvc(new ArmSvc() {
                    @Override
                    public int handle(Emulator emulator) {
                        int image_index = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
                        MachOModule module = (MachOModule) loader.getLoadedModules().toArray(new Module[0])[image_index];
                        if (module.nameBlock == null) {
                            byte[] name = module.name.getBytes();
                            module.nameBlock = loader.malloc(name.length + 1, true);
                            module.nameBlock.getPointer().write(0, name, 0, name.length);
                            module.nameBlock.getPointer().setByte(name.length, (byte) 0);
                        }
                        return (int) module.nameBlock.getPointer().peer;
                    }
                }).peer;
            }
            if ("__dyld_get_image_header".equals(symbolName)) {
                return svcMemory.registerSvc(new ArmSvc() {
                    @Override
                    public int handle(Emulator emulator) {
                        int image_index = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
                        MachOModule module = (MachOModule) loader.getLoadedModules().toArray(new Module[0])[image_index];
                        return (int) module.base;
                    }
                }).peer;
            }
        }
        return 0;
    }

}
