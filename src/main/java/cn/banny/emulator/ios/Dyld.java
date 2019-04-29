package cn.banny.emulator.ios;

import cn.banny.emulator.spi.Dlfcn;
import cn.banny.emulator.Emulator;
import cn.banny.emulator.Module;
import cn.banny.emulator.arm.ArmSvc;
import cn.banny.emulator.memory.SvcMemory;
import io.kaitai.MachO;
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
        if ("_dyld_get_program_sdk_version".equals(symbolName)) {
            System.err.println("_dyld_get_program_sdk_version=" + libraryName);
        }
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
                        if (module.pathBlock == null) {
                            byte[] path = module.path.getBytes();
                            module.pathBlock = loader.malloc(path.length + 1, true);
                            module.pathBlock.getPointer().write(0, path, 0, path.length);
                            module.pathBlock.getPointer().setByte(path.length, (byte) 0);
                        }
                        return (int) module.pathBlock.getPointer().peer;
                    }
                }).peer;
            }
            if ("__dyld_get_image_header".equals(symbolName) || "__dyld_get_image_vmaddr_slide".equals(symbolName)) {
                return svcMemory.registerSvc(new ArmSvc() {
                    @Override
                    public int handle(Emulator emulator) {
                        int image_index = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
                        MachOModule module = (MachOModule) loader.getLoadedModules().toArray(new Module[0])[image_index];
                        return (int) module.base;
                    }
                }).peer;
            }
            if ("_dyld_get_program_sdk_version".equals(symbolName)) {
                return svcMemory.registerSvc(new ArmSvc() {
                    @Override
                    public int handle(Emulator emulator) {
                        MachO.VersionMinCommand sdkVersion = loader.sdkVersion;
                        if (sdkVersion == null) {
                            return 0;
                        } else {
                            MachO.Version sdk = sdkVersion.sdk();
                            return (sdk.p1() << 24) | (sdk.minor() << 16) | (sdk.major() << 8) | sdk.release();
                        }
                    }
                }).peer;
            }
        }
        return 0;
    }

}
