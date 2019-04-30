package cn.banny.emulator.ios;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.Module;
import cn.banny.emulator.arm.ArmSvc;
import cn.banny.emulator.memory.SvcMemory;
import cn.banny.emulator.pointer.UnicornPointer;
import cn.banny.emulator.spi.Dlfcn;
import com.sun.jna.Pointer;
import io.kaitai.MachO;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.ArmConst;
import unicorn.Unicorn;

import java.util.Arrays;

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
                log.debug("checkHook symbolName=" + symbolName + ", old=0x" + Long.toHexString(old) + ", libraryName=" + libraryName);
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
            if ("__dyld_get_image_slide".equals(symbolName)) {
                return svcMemory.registerSvc(new ArmSvc() {
                    @Override
                    public int handle(Emulator emulator) {
                        UnicornPointer mh = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                        log.debug("__dyld_get_image_slide mh=" + mh);
                        return (int) mh.peer;
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

            /*
             * _dyld_register_func_for_add_image registers the specified function to be
             * called when a new image is added (a bundle or a dynamic shared library) to
             * the program.  When this function is first registered it is called for once
             * for each image that is currently part of the program.
             */
            if ("__dyld_register_func_for_add_image".equals(symbolName)) {
                return svcMemory.registerSvc(new ArmSvc() {
                    @Override
                    public UnicornPointer onRegister(SvcMemory svcMemory, int svcNumber) {
                        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm, KeystoneMode.Arm)) {
                            KeystoneEncoded encoded = keystone.assemble(Arrays.asList(
                                    "push {r4-r7, lr}",
                                    "svc #0x" + Integer.toHexString(svcNumber),
                                    "pop {r7}", // manipulated stack in dlopen
                                    "cmp r7, #0",
                                    "subne lr, pc, #16", // jump to pop {r7}
                                    "popne {r0-r1}", // (headerType *mh, unsigned long	vmaddr_slide)
                                    "bxne r7", // call init array
                                    "pop {r0, r4-r7, pc}")); // with return address
                            byte[] code = encoded.getMachineCode();
                            UnicornPointer pointer = svcMemory.allocate(code.length);
                            pointer.write(0, code, 0, code.length);
                            return pointer;
                        }
                    }
                    @Override
                    public int handle(Emulator emulator) {
                        final Unicorn unicorn = emulator.getUnicorn();

                        UnicornPointer callback = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                        if (log.isDebugEnabled()) {
                            log.debug("__dyld_register_func_for_add_image callback=" + callback);
                        }

                        Pointer pointer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_SP);
                        try {
                            pointer = pointer.share(-4); // return value
                            pointer.setInt(0, 0);

                            pointer = pointer.share(-4); // NULL-terminated
                            pointer.setInt(0, 0);

                            if (callback != null && !loader.addImageCallbacks.contains(callback)) {
                                loader.addImageCallbacks.add(callback);

                                for (Module md : loader.getLoadedModules()) {
                                    Log log = LogFactory.getLog("cn.banny.emulator.ios." + md.name);

                                    // (headerType *mh, unsigned long	vmaddr_slide)
                                    pointer = pointer.share(-4);
                                    pointer.setInt(0, (int) md.base);
                                    pointer = pointer.share(-4);
                                    pointer.setInt(0, (int) md.base);

                                    if (log.isDebugEnabled()) {
                                        log.debug("[" + md.name + "]PushAddImageFunction: 0x" + Long.toHexString(md.base));
                                    }
                                    pointer = pointer.share(-4); // callback
                                    pointer.setPointer(0, callback);
                                }
                            }

                            return 0;
                        } finally {
                            unicorn.reg_write(ArmConst.UC_ARM_REG_SP, ((UnicornPointer) pointer).peer);
                        }
                    }
                }).peer;
            }

            /*
             * _dyld_register_func_for_remove_image registers the specified function to be
             * called when an image is removed (a bundle or a dynamic shared library) from
             * the program.
             */
            if ("__dyld_register_func_for_remove_image".equals(symbolName)) {
                return svcMemory.registerSvc(new ArmSvc() {
                    @Override
                    public int handle(Emulator emulator) {
                        Pointer callback = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                        if (log.isDebugEnabled()) {
                            log.debug("__dyld_register_func_for_remove_image callback=" + callback);
                        }
                        return 0;
                    }
                }).peer;
            }

            // TODO call tlv_initializer()
            if ("__dyld_initializer".equals(symbolName)) {
                return svcMemory.registerSvc(new ArmSvc() {
                    @Override
                    public int handle(Emulator emulator) {
                        log.debug("__dyld_initializer");
                        return 0;
                    }
                }).peer;
            }
        }
        return 0;
    }

}
