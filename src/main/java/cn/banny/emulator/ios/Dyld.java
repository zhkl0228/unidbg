package cn.banny.emulator.ios;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.Module;
import cn.banny.emulator.Symbol;
import cn.banny.emulator.arm.ArmSvc;
import cn.banny.emulator.memory.Memory;
import cn.banny.emulator.memory.SvcMemory;
import cn.banny.emulator.pointer.UnicornPointer;
import cn.banny.emulator.spi.Dlfcn;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.ArmConst;
import unicorn.Unicorn;

import java.io.IOException;
import java.util.Arrays;

public class Dyld implements Dlfcn {

    private static final Log log = LogFactory.getLog(Dyld.class);

    private final MachOLoader loader;

    private final UnicornPointer error;

    public Dyld(MachOLoader loader, SvcMemory svcMemory) {
        this.loader = loader;

        error = svcMemory.allocate(0x40);
        assert error != null;
        error.setMemory(0, 0x40, (byte) 0);
    }

    private long _OSAtomicCompareAndSwap32Barrier;
    private long _OSAtomicCompareAndSwap64Barrier;

    private Pointer __dyld_image_count;
    private Pointer __dyld_get_image_name;
    private Pointer __dyld_get_image_header;
    private Pointer __dyld_get_image_slide;
    private Pointer __dyld_register_func_for_add_image;
    private Pointer __dyld_register_func_for_remove_image;
    private Pointer __dyld_register_thread_helpers;

    int _stub_binding_helper() {
        log.info("dyldLazyBinder");
        return 0;
    }

    private Pointer __dyld_dlsym;

    int _dyld_func_lookup(Emulator emulator, String name, Pointer address) {
        final SvcMemory svcMemory = emulator.getSvcMemory();
        switch (name) {
            case "__dyld_dlsym":
                if (__dyld_dlsym == null) {
                    __dyld_dlsym = svcMemory.registerSvc(new ArmSvc() {
                        @Override
                        public int handle(Emulator emulator) {
                            long handle = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R0)).intValue() & 0xffffffffL;
                            Pointer symbol = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                            if (log.isDebugEnabled()) {
                                log.debug("__dyld_dlsym handle=0x" + Long.toHexString(handle) + ", symbol=" + symbol.getString(0));
                            }
                            return dlsym(emulator.getMemory(), (int) handle, symbol.getString(0));
                        }
                    });
                }
                address.setPointer(0, __dyld_dlsym);
                return 1;
            case "__dyld_get_image_name":
                if (__dyld_get_image_name == null) {
                    __dyld_get_image_name = svcMemory.registerSvc(new ArmSvc() {
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
                    });
                }
                address.setPointer(0, __dyld_get_image_name);
                return 1;
            case "__dyld_get_image_header":
            case "__dyld_get_image_vmaddr_slide":
                if (__dyld_get_image_header == null) {
                    __dyld_get_image_header = svcMemory.registerSvc(new ArmSvc() {
                        @Override
                        public int handle(Emulator emulator) {
                            int image_index = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
                            MachOModule module = (MachOModule) loader.getLoadedModules().toArray(new Module[0])[image_index];
                            return (int) module.base;
                        }
                    });
                }
                address.setPointer(0, __dyld_get_image_header);
                return 1;
            case "__dyld_image_count":
                if (__dyld_image_count == null) {
                    __dyld_image_count = svcMemory.registerSvc(new ArmSvc() {
                        @Override
                        public int handle(Emulator emulator) {
                            return loader.getLoadedModules().size();
                        }
                    });
                }
                address.setPointer(0, __dyld_image_count);
                return 1;
            case "__dyld_register_thread_helpers":
                if (__dyld_register_thread_helpers == null) {
                    __dyld_register_thread_helpers = svcMemory.registerSvc(new ArmSvc() {
                        @Override
                        public int handle(Emulator emulator) {
                            Pointer helpers = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                            log.debug("registerThreadHelpers helpers=" + helpers);
                            return 0;
                        }
                    });
                }
                address.setPointer(0, __dyld_register_thread_helpers);
                return 1;
            case "__dyld_register_func_for_remove_image":
                /*
                 * _dyld_register_func_for_remove_image registers the specified function to be
                 * called when an image is removed (a bundle or a dynamic shared library) from
                 * the program.
                 */
                if (__dyld_register_func_for_remove_image == null) {
                    __dyld_register_func_for_remove_image = svcMemory.registerSvc(new ArmSvc() {
                        @Override
                        public int handle(Emulator emulator) {
                            Pointer callback = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                            if (log.isDebugEnabled()) {
                                log.debug("__dyld_register_func_for_remove_image callback=" + callback);
                            }
                            return 0;
                        }
                    });
                }
                address.setPointer(0, __dyld_register_func_for_remove_image);
                return 1;
            case "__dyld_get_image_slide":
                if (__dyld_get_image_slide == null) {
                    __dyld_get_image_slide = svcMemory.registerSvc(new ArmSvc() {
                        @Override
                        public int handle(Emulator emulator) {
                            UnicornPointer mh = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                            log.debug("__dyld_get_image_slide mh=" + mh);
                            return (int) mh.peer;
                        }
                    });
                }
                address.setPointer(0, __dyld_get_image_slide);
                return 1;
            case "__dyld_register_func_for_add_image":
                /*
                 * _dyld_register_func_for_add_image registers the specified function to be
                 * called when a new image is added (a bundle or a dynamic shared library) to
                 * the program.  When this function is first registered it is called for once
                 * for each image that is currently part of the program.
                 */
                if (__dyld_register_func_for_add_image == null) {
                    __dyld_register_func_for_add_image = svcMemory.registerSvc(new ArmSvc() {
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
                    });
                }
                address.setPointer(0, __dyld_register_func_for_add_image);
                return 1;
            default:
                log.info("_dyld_func_lookup name=" + name + ", address=" + address);
                break;
        }
        address.setPointer(0, null);
        return 0;
    }

    private long __NSGetEnviron;
    private long __NSGetMachExecuteHeader;

    @Override
    public long hook(SvcMemory svcMemory, String libraryName, String symbolName, final long old) {
        if ("libsystem_c.dylib".equals(libraryName)) {
            if ("__NSGetEnviron".equals(symbolName)) {
                if (__NSGetEnviron == 0) {
                    __NSGetEnviron = svcMemory.registerSvc(new ArmSvc() {
                        @Override
                        public int handle(Emulator emulator) {
                            return (int) loader._NSGetEnviron.peer;
                        }
                    }).peer;
                }
                return __NSGetEnviron;
            }
            if ("__NSGetMachExecuteHeader".equals(symbolName)) {
                if (__NSGetMachExecuteHeader == 0) {
                    __NSGetMachExecuteHeader = svcMemory.registerSvc(new ArmSvc() {
                        @Override
                        public int handle(Emulator emulator) {
                            Module module = loader.findModule("libSystem.B.dylib");
                            if (module == null) {
                                throw new NullPointerException();
                            }
                            return (int) module.base;
                        }
                    }).peer;
                }
                return __NSGetMachExecuteHeader;
            }
        }

        if ("libsystem_platform.dylib".equals(libraryName)) {
            if ("_OSAtomicCompareAndSwap32Barrier".equals(symbolName)) {
                if (_OSAtomicCompareAndSwap32Barrier == 0) {
                    _OSAtomicCompareAndSwap32Barrier = svcMemory.registerSvc(new ArmSvc() {
                        @Override
                        public int handle(Emulator emulator) {
                            Unicorn unicorn = emulator.getUnicorn();
                            int oldValue = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
                            int newValue = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
                            Pointer theValue = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                            if (log.isDebugEnabled()) {
                                log.debug("_OSAtomicCompareAndSwap32Barrier oldValue=0x" + Integer.toHexString(oldValue) + ", newValue=0x" + Integer.toHexString(newValue) + ", theValue=" + theValue + ", value=0x" + theValue.getInt(0));
                            }
                            if (theValue.getInt(0) == oldValue) {
                                theValue.setInt(0, newValue);
                                return 1;
                            } else {
                                return 0;
                            }
                        }
                    }).peer;
                }
                return _OSAtomicCompareAndSwap32Barrier;
            }

            if ("_OSAtomicCompareAndSwap64Barrier".equals(symbolName)) {
                if (_OSAtomicCompareAndSwap64Barrier == 0) {
                    _OSAtomicCompareAndSwap64Barrier = svcMemory.registerSvc(new ArmSvc() {
                        @Override
                        public int handle(Emulator emulator) {
                            Unicorn unicorn = emulator.getUnicorn();
                            int r0 = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
                            long r1 = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
                            long oldValue = r0 | (r1 << 32);
                            int r2 = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
                            long r3 = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
                            long newValue = r2 | (r3 << 32);
                            Pointer sp = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_SP);
                            Pointer theValue = sp.getPointer(0);
                            if (log.isDebugEnabled()) {
                                log.debug("_OSAtomicCompareAndSwap64Barrier oldValue=0x" + Long.toHexString(oldValue) +
                                        ", newValue=0x" + Long.toHexString(newValue) +
                                        ", theValue=" + theValue +
                                        ", value=0x" + Long.toHexString(theValue.getLong(0)));
                            }
                            if (theValue.getLong(0) == oldValue) {
                                theValue.setLong(0, newValue);
                                return 1;
                            } else {
                                return 0;
                            }
                        }
                    }).peer;
                }
                return _OSAtomicCompareAndSwap64Barrier;
            }
        } else if ("libdyld.dylib".equals(libraryName)) {
            if (log.isDebugEnabled()) {
                log.debug("checkHook symbolName=" + symbolName + ", old=0x" + Long.toHexString(old) + ", libraryName=" + libraryName);
            }
            /*if ("_dyld_get_program_sdk_version".equals(symbolName)) {
                if (_dyld_get_program_sdk_version == 0) {
                    _dyld_get_program_sdk_version = svcMemory.registerSvc(new ArmSvc() {
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
                return _dyld_get_program_sdk_version;
            }*/
        }
        return 0;
    }

    private int dlsym(Memory memory, long handle, String symbolName) {
        try {
            Symbol symbol = memory.dlsym(handle, symbolName);
            if (symbol == null) {
                this.error.setString(0, "Find symbol " + symbol + " failed");
                return 0;
            }
            return (int) symbol.getAddress();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

}
