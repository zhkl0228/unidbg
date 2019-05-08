package cn.banny.emulator.ios;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.Module;
import cn.banny.emulator.Symbol;
import cn.banny.emulator.arm.AbstractARMEmulator;
import cn.banny.emulator.arm.ArmHook;
import cn.banny.emulator.arm.ArmSvc;
import cn.banny.emulator.arm.HookStatus;
import cn.banny.emulator.ios.struct.*;
import cn.banny.emulator.memory.Memory;
import cn.banny.emulator.memory.SvcMemory;
import cn.banny.emulator.pointer.UnicornPointer;
import cn.banny.emulator.pointer.UnicornStructure;
import cn.banny.emulator.spi.Dlfcn;
import cn.banny.emulator.spi.InitFunction;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static cn.banny.emulator.ios.MachO.LARGE_THRESHOLD;

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

    private Pointer __dyld_image_count;
    private Pointer __dyld_get_image_name;
    private Pointer __dyld_get_image_header;
    private Pointer __dyld_get_image_vmaddr_slide;
    private Pointer __dyld_get_image_slide;
    private Pointer __dyld_register_func_for_add_image;
    private Pointer __dyld_register_func_for_remove_image;
    private Pointer __dyld_register_thread_helpers;
    private Pointer __dyld_dyld_register_image_state_change_handler;
    private Pointer __dyld_image_path_containing_address;

    int _stub_binding_helper() {
        log.info("dyldLazyBinder");
        return 0;
    }

    private Pointer __dyld_dlopen;
    private Pointer __dyld_dlsym;
    private Pointer __dyld_dladdr;
    private long _os_trace_redirect_func;

    int _dyld_func_lookup(Emulator emulator, String name, Pointer address) {
        final SvcMemory svcMemory = emulator.getSvcMemory();
        switch (name) {
            case "__dyld_get_image_name":
                if (__dyld_get_image_name == null) {
                    __dyld_get_image_name = svcMemory.registerSvc(new ArmSvc() {
                        @Override
                        public int handle(Emulator emulator) {
                            int image_index = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
                            Module[] modules = loader.getLoadedModules().toArray(new Module[0]);
                            if (image_index < 0 || image_index >= modules.length) {
                                return 0;
                            }
                            MachOModule module = (MachOModule) modules[image_index];
                            return (int) module.createPathMemory(svcMemory).peer;
                        }
                    });
                }
                address.setPointer(0, __dyld_get_image_name);
                return 1;
            case "__dyld_get_image_header":
                if (__dyld_get_image_header == null) {
                    __dyld_get_image_header = svcMemory.registerSvc(new ArmSvc() {
                        @Override
                        public int handle(Emulator emulator) {
                            int image_index = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
                            Module[] modules = loader.getLoadedModules().toArray(new Module[0]);
                            if (image_index < 0 || image_index >= modules.length) {
                                return 0;
                            }
                            MachOModule module = (MachOModule) modules[image_index];
                            return (int) module.machHeader;
                        }
                    });
                }
                address.setPointer(0, __dyld_get_image_header);
                return 1;
            case "__dyld_get_image_slide":
                if (__dyld_get_image_slide == null) {
                    __dyld_get_image_slide = svcMemory.registerSvc(new ArmSvc() {
                        @Override
                        public int handle(Emulator emulator) {
                            UnicornPointer mh = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                            log.debug("__dyld_get_image_slide mh=" + mh);
                            return mh == null ? 0 : computeSlide(emulator, mh.peer);
                        }
                    });
                }
                address.setPointer(0, __dyld_get_image_slide);
                return 1;
            case "__dyld_get_image_vmaddr_slide":
                if (__dyld_get_image_vmaddr_slide == null) {
                    __dyld_get_image_vmaddr_slide = svcMemory.registerSvc(new ArmSvc() {
                        @Override
                        public int handle(Emulator emulator) {
                            int image_index = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
                            log.debug("__dyld_get_image_vmaddr_slide index=" + image_index);
                            Module[] modules = loader.getLoadedModules().toArray(new Module[0]);
                            if (image_index < 0 || image_index >= modules.length) {
                                return 0;
                            }
                            MachOModule module = (MachOModule) modules[image_index];
                            return computeSlide(emulator, module.machHeader);
                        }
                    });
                }
                address.setPointer(0, __dyld_get_image_vmaddr_slide);
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
            case "__dyld_dlopen":
                if (__dyld_dlopen == null) {
                    __dyld_dlopen = svcMemory.registerSvc(new ArmSvc() {
                        @Override
                        public UnicornPointer onRegister(SvcMemory svcMemory, int svcNumber) {
                            try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm, KeystoneMode.Arm)) {
                                KeystoneEncoded encoded = keystone.assemble(Arrays.asList(
                                        "push {r4-r7, lr}",
                                        "svc #0x" + Integer.toHexString(svcNumber),
                                        "pop {r7}", // manipulated stack in dlopen
                                        "cmp r7, #0",
                                        "subne lr, pc, #16", // jump to pop {r7}
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
                            Pointer path = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                            int mode = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
                            if (log.isDebugEnabled()) {
                                log.debug("__dyld_dlopen path=" + path.getString(0) + ", mode=" + mode);
                            }
                            return dlopen(emulator.getMemory(), path.getString(0), emulator);
                        }
                    });
                }
                address.setPointer(0, __dyld_dlopen);
                return 1;
            case "__dyld_dladdr":
                if (__dyld_dladdr == null) {
                    __dyld_dladdr = svcMemory.registerSvc(new ArmSvc() {
                        @Override
                        public int handle(Emulator emulator) {
                            long addr = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R0)).intValue() & 0xffffffffL;
                            Pointer info = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                            if (log.isDebugEnabled()) {
                                log.debug("__dyld_dladdr addr=0x" + Long.toHexString(addr) + ", info=" + info);
                            }
                            MachOModule module = (MachOModule) loader.findModuleByAddress(addr);
                            if (module == null) {
                                return 0;
                            }

                            MachOSymbol symbol = (MachOSymbol) module.findNearestSymbolByAddress(addr);

                            DlInfo dlInfo = new DlInfo(info);
                            dlInfo.dli_fname = module.createPathMemory(svcMemory);
                            dlInfo.dli_fbase = UnicornPointer.pointer(emulator, module.base);
                            if (symbol != null) {
                                dlInfo.dli_sname = symbol.createNameMemory(svcMemory);
                                dlInfo.dli_saddr = UnicornPointer.pointer(emulator, symbol.getAddress());
                            }
                            dlInfo.pack();
                            return 1;
                        }
                    });
                }
                address.setPointer(0, __dyld_dladdr);
                return 1;
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

                            String symbolName = symbol.getString(0);
                            if ((int) handle == MachO.RTLD_MAIN_ONLY && "_os_trace_redirect_func".equals(symbolName)) {
                                if (_os_trace_redirect_func == 0) {
                                    _os_trace_redirect_func = svcMemory.registerSvc(new ArmSvc() {
                                        @Override
                                        public int handle(Emulator emulator) {
                                            Pointer msg = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
//                                            Inspector.inspect(msg.getByteArray(0, 16), "_os_trace_redirect_func msg=" + msg);
                                            System.err.println("_os_trace_redirect_func msg=" + msg.getString(0));
                                            return 1;
                                        }
                                    }).peer;
                                }
                                return (int) _os_trace_redirect_func;
                            }

                            return dlsym(emulator.getMemory(), (int) handle, symbolName);
                        }
                    });
                }
                address.setPointer(0, __dyld_dlsym);
                return 1;
            case "__dyld_register_thread_helpers":
                if (__dyld_register_thread_helpers == null) {
                    __dyld_register_thread_helpers = svcMemory.registerSvc(new ArmSvc() {
                        @Override
                        public int handle(Emulator emulator) {
                            Pointer helpers = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                            log.info("registerThreadHelpers helpers=" + helpers);
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
                                        } else if (Dyld.log.isDebugEnabled()) {
                                            Dyld.log.debug("[" + md.name + "]PushAddImageFunction: 0x" + Long.toHexString(md.base));
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
            case "__dyld_dyld_register_image_state_change_handler":
                if (__dyld_dyld_register_image_state_change_handler == null) {
                    __dyld_dyld_register_image_state_change_handler = svcMemory.registerSvc(new ArmSvc() {
                        @Override
                        public UnicornPointer onRegister(SvcMemory svcMemory, int svcNumber) {
                            try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm, KeystoneMode.Arm)) {
                                KeystoneEncoded encoded = keystone.assemble(Arrays.asList(
                                        "push {r4-r7, lr}",
                                        "svc #0x" + Integer.toHexString(svcNumber),
                                        "pop {r7}", // manipulated stack in dlopen
                                        "cmp r7, #0",
                                        "subne lr, pc, #16", // jump to pop {r7}
                                        "popne {r0-r2}", // const char* (*dyld_image_state_change_handler)(enum dyld_image_states state, uint32_t infoCount, const struct dyld_image_info info[])
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
                            Unicorn unicorn = emulator.getUnicorn();
                            int state = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
                            int batch = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
                            Pointer handler = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                            DyldImageInfo[] imageInfos;
                            if (batch == 1) {
                                imageInfos = registerImageStateBatchChangeHandler(state, handler, emulator);
                            } else {
                                imageInfos = registerImageStateSingleChangeHandler(state, handler, emulator);
                            }

                            Pointer pointer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_SP);
                            try {
                                pointer = pointer.share(-4); // return value
                                pointer.setInt(0, 0);

                                pointer = pointer.share(-4); // NULL-terminated
                                pointer.setInt(0, 0);

                                if (handler != null && imageInfos != null) {
                                    // (*dyld_image_state_change_handler)(enum dyld_image_states state, uint32_t infoCount, const struct dyld_image_info info[])
                                    pointer = pointer.share(-4);
                                    pointer.setPointer(0, imageInfos.length == 0 ? null : imageInfos[0].getPointer());
                                    pointer = pointer.share(-4);
                                    pointer.setInt(0, imageInfos.length);
                                    pointer = pointer.share(-4);
                                    pointer.setInt(0, state);

                                    if (log.isDebugEnabled()) {
                                        log.debug("PushImageHandlerFunction: " + handler + ", imageSize=" + imageInfos.length);
                                    }
                                    pointer = pointer.share(-4); // handler
                                    pointer.setPointer(0, handler);
                                }

                                return 0;
                            } finally {
                                unicorn.reg_write(ArmConst.UC_ARM_REG_SP, ((UnicornPointer) pointer).peer);
                            }
                        }
                    });
                }
                address.setPointer(0, __dyld_dyld_register_image_state_change_handler);
                return 1;
            case "__dyld_image_path_containing_address":
                if (__dyld_image_path_containing_address == null) {
                    __dyld_image_path_containing_address = svcMemory.registerSvc(new ArmSvc() {
                        @Override
                        public int handle(Emulator emulator) {
                            UnicornPointer address = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                            MachOModule module = (MachOModule) loader.findModuleByAddress(address.peer);
                            if (log.isDebugEnabled()) {
                                log.debug("__dyld_image_path_containing_address address=" + address + ", module=" + module);
                            }
                            if (module != null) {
                                return (int) module.createPathMemory(svcMemory).peer;
                            } else {
                                return 0;
                            }
                        }
                    });
                }
                address.setPointer(0, __dyld_image_path_containing_address);
                return 1;
            default:
                log.info("_dyld_func_lookup name=" + name + ", address=" + address);
                break;
        }
        address.setPointer(0, null);
        return 0;
    }

    private int computeSlide(Emulator emulator, long machHeader) {
        if (emulator.getPointerSize() == 4) {
            Pointer pointer = UnicornPointer.pointer(emulator, machHeader);
            assert pointer != null;
            MachHeader header = new MachHeader(pointer);
            Pointer loadPointer = pointer.share(header.size());
            for (int i = 0; i < header.ncmds; i++) {
                LoadCommand loadCommand = new LoadCommand(loadPointer);
                loadCommand.unpack();
                if (loadCommand.type == io.kaitai.MachO.LoadCommandType.SEGMENT.id()) {
                    SegmentCommand segmentCommand = new SegmentCommand(loadPointer);
                    segmentCommand.unpack();

                    if ("__TEXT".equals(new String(segmentCommand.segname).trim())) {
                        return (int) (machHeader - segmentCommand.vmaddr);
                    }
                }
                loadPointer = loadPointer.share(loadCommand.size);
            }
            return 0;
        } else {
            throw new UnsupportedOperationException();
        }
    }

    private int dlopen(Memory memory, String path, Emulator emulator) {
        Unicorn unicorn = emulator.getUnicorn();
        Pointer pointer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_SP);
        try {
            Module module = memory.dlopen(path, false);
            if (module == null) {
                pointer = pointer.share(-4); // return value
                pointer.setInt(0, 0);

                pointer = pointer.share(-4); // NULL-terminated
                pointer.setInt(0, 0);

                log.info("dlopen failed: " + path);
                this.error.setString(0, "Resolve library " + path + " failed");
                return 0;
            } else {
                pointer = pointer.share(-4); // return value
                pointer.setInt(0, (int) module.base);

                pointer = pointer.share(-4); // NULL-terminated
                pointer.setInt(0, 0);

                for (Module m : memory.getLoadedModules()) {
                    MachOModule mm = (MachOModule) m;
                    if (mm.hasUnresolvedSymbol()) {
                        continue;
                    }
                    for (InitFunction initFunction : mm.initFunctionList) {
                        if (initFunction.addresses != null) {
                            for (long addr : initFunction.addresses) {
                                if (addr != 0 && addr != -1) {
                                    log.debug("[" + mm.name + "]PushModInitFunction: 0x" + Long.toHexString(addr));
                                    pointer = pointer.share(-4); // init array
                                    pointer.setInt(0, (int) (mm.base + addr));
                                }
                            }
                        }
                    }
                    mm.initFunctionList.clear();
                }

                for (Module m : memory.getLoadedModules()) {
                    MachOModule mm = (MachOModule) m;
                    for (InitFunction routine : mm.routines) {
                        for (long addr : routine.addresses) {
                            if (addr != 0 && addr != -1) {
                                log.debug("[" + mm.name + "]PushRoutineFunction: 0x" + Long.toHexString(addr));
                                pointer = pointer.share(-4); // routines
                                pointer.setInt(0, (int) (mm.base + addr));
                            }
                        }
                    }
                    mm.routines.clear();
                }

                return (int) module.base;
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        } finally {
            unicorn.reg_write(ArmConst.UC_ARM_REG_SP, ((UnicornPointer) pointer).peer);
        }
    }

    private static final int dyld_image_state_bound = 40;
    private static final int dyld_image_state_dependents_initialized = 45; // Only single notification for this
    private static final int dyld_image_state_terminated = 60; // Only single notification for this

    private DyldImageInfo[] registerImageStateBatchChangeHandler(int state, Pointer handler, Emulator emulator) {
        if (log.isDebugEnabled()) {
            log.debug("registerImageStateBatchChangeHandler state=" + state + ", handler=" + handler);
        }

        if (state != dyld_image_state_bound) {
            throw new UnsupportedOperationException("state=" + state);
        }

        return generateDyldImageInfo(emulator);
    }

    private DyldImageInfo[] generateDyldImageInfo(Emulator emulator) {
        List<DyldImageInfo> list = new ArrayList<>(loader.getLoadedModules().size());
        int elementSize = UnicornStructure.calculateSize(DyldImageInfo.class);
        Pointer pointer = emulator.getSvcMemory().allocate(elementSize * loader.getLoadedModules().size());
        for (Module module : loader.getLoadedModules()) {
            MachOModule mm = (MachOModule) module;
            DyldImageInfo info = new DyldImageInfo(pointer);
            info.imageFilePath = mm.createPathMemory(emulator.getSvcMemory());
            info.imageLoadAddress = UnicornPointer.pointer(emulator, module.base);
            info.imageFileModDate = 0;
            info.pack();
            list.add(info);
            pointer = pointer.share(elementSize);
        }
        return list.toArray(new DyldImageInfo[0]);
    }

    private DyldImageInfo[] registerImageStateSingleChangeHandler(int state, Pointer handler, Emulator emulator) {
        if (log.isDebugEnabled()) {
            log.debug("registerImageStateSingleChangeHandler state=" + state + ", handler=" + handler);
        }

        if (state == dyld_image_state_terminated) {
            return null;
        }

        if (state != dyld_image_state_dependents_initialized) {
            throw new UnsupportedOperationException("state=" + state);
        }

        return generateDyldImageInfo(emulator);
    }

//    private long __NSGetMachExecuteHeader;
    private long _abort;

    @Override
    public long hook(SvcMemory svcMemory, String libraryName, String symbolName, final long old) {
        if ("libsystem_c.dylib".equals(libraryName)) {
            if ("_abort".equals(symbolName)) {
                if (_abort == 0) {
                    _abort = svcMemory.registerSvc(new ArmSvc() {
                        @Override
                        public int handle(Emulator emulator) {
                            System.err.println("abort");
                            emulator.getUnicorn().reg_write(ArmConst.UC_ARM_REG_LR, AbstractARMEmulator.LR);
                            return 0;
                        }
                    }).peer;
                }
                return _abort;
            }
            /*if ("__NSGetMachExecuteHeader".equals(symbolName)) {
                if (__NSGetMachExecuteHeader == 0) {
                    __NSGetMachExecuteHeader = svcMemory.registerSvc(new ArmSvc() {
                        @Override
                        public int handle(Emulator emulator) {
                            Module module = loader.NSGetMachExecuteHeader();
                            if (log.isDebugEnabled()) {
                                log.debug("__NSGetMachExecuteHeader module=" + module);
                            }
                            if (module == null) {
                                throw new NullPointerException();
                            } else {
                                return (int) module.base;
                            }
                        }
                    }).peer;
                }
                return __NSGetMachExecuteHeader;
            }*/
        } else if ("libsystem_malloc.dylib".equals(libraryName)) {
            {
                Log log = LogFactory.getLog("cn.banny.emulator.ios.malloc");
                if (log.isDebugEnabled()) {
                    log.debug("checkHook symbolName=" + symbolName + ", old=0x" + Long.toHexString(old) + ", libraryName=" + libraryName);
                } else if (Dyld.log.isDebugEnabled()) {
                    Dyld.log.debug("checkHook symbolName=" + symbolName + ", old=0x" + Long.toHexString(old) + ", libraryName=" + libraryName);
                }
            }
            /*if ("_free".equals(symbolName)) {
                if (_free == 0) {
                    _free = svcMemory.registerSvc(new ArmHook() {
                        @Override
                        protected HookStatus hook(Unicorn u, Emulator emulator) {
                            UnicornPointer pointer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                            if ((pointer.peer & (emulator.getPageAlign() - 1)) != 0) {
                                log.info("_free pointer=" + pointer);
                            }
                            return HookStatus.RET(u, old);
                        }
                    }).peer;
                }
                return _free;
            }*/
            if ("_malloc".equals(symbolName)) {
                if (_malloc == 0) {
                    _malloc = svcMemory.registerSvc(new ArmHook() {
                        @Override
                        protected HookStatus hook(Unicorn u, Emulator emulator) {
                            int size = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
                            if (size <= LARGE_THRESHOLD) {
                                Log log = LogFactory.getLog("cn.banny.emulator.ios.malloc");
                                if (log.isDebugEnabled()) {
                                    log.debug("Fake _malloc size=" + size);
                                } else if (Dyld.log.isDebugEnabled()) {
                                    Dyld.log.debug("Fake _malloc size=" + size);
                                }
                                u.reg_write(ArmConst.UC_ARM_REG_R0, LARGE_THRESHOLD + 1);
                            }
                            return HookStatus.RET(u, old);
                        }
                    }).peer;
                }
                return _malloc;
            }
            if ("_valloc".equals(symbolName)) {
                if (_valloc == 0) {
                    _valloc = svcMemory.registerSvc(new ArmHook() {
                        @Override
                        protected HookStatus hook(Unicorn u, Emulator emulator) {
                            int size = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
                            if (size <= LARGE_THRESHOLD) {
                                Log log = LogFactory.getLog("cn.banny.emulator.ios.malloc");
                                if (log.isDebugEnabled()) {
                                    log.debug("Fake _valloc size=" + size);
                                } else if (Dyld.log.isDebugEnabled()) {
                                    Dyld.log.debug("Fake _valloc size=" + size);
                                }
                                u.reg_write(ArmConst.UC_ARM_REG_R0, LARGE_THRESHOLD + 1);
                            }
                            return HookStatus.RET(u, old);
                        }
                    }).peer;
                }
                return _valloc;
            }
            if ("_realloc".equals(symbolName)) {
                if (_realloc == 0) {
                    _realloc = svcMemory.registerSvc(new ArmHook() {
                        @Override
                        protected HookStatus hook(Unicorn u, Emulator emulator) {
                            Pointer pointer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                            int size = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
                            if (size <= LARGE_THRESHOLD) {
                                Log log = LogFactory.getLog("cn.banny.emulator.ios.malloc");
                                if (log.isDebugEnabled()) {
                                    log.debug("Fake _realloc pointer=" + pointer + ", size=" + size);
                                } else if (Dyld.log.isDebugEnabled()) {
                                    Dyld.log.debug("Fake _realloc pointer=" + pointer + ", size=" + size);
                                }
                                u.reg_write(ArmConst.UC_ARM_REG_R1, LARGE_THRESHOLD + 1);
                            }
                            return HookStatus.RET(u, old);
                        }
                    }).peer;
                }
                return _realloc;
            }
            if ("_calloc".equals(symbolName)) {
                if (_calloc == 0) {
                    _calloc = svcMemory.registerSvc(new ArmHook() {
                        @Override
                        protected HookStatus hook(Unicorn u, Emulator emulator) {
                            int count = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
                            int size = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
                            if (count * size <= LARGE_THRESHOLD) {
                                Log log = LogFactory.getLog("cn.banny.emulator.ios.malloc");
                                if (log.isDebugEnabled()) {
                                    log.debug("Fake _calloc count=" + count + ", size=" + size);
                                } else if (Dyld.log.isDebugEnabled()) {
                                    Dyld.log.debug("Fake _calloc count=" + count + ", size=" + size);
                                }
                                u.reg_write(ArmConst.UC_ARM_REG_R0, 1);
                                u.reg_write(ArmConst.UC_ARM_REG_R1, LARGE_THRESHOLD + 1);
                            }
                            return HookStatus.RET(u, old);
                        }
                    }).peer;
                }
                return _calloc;
            }
            if ("_malloc_zone_malloc".equals(symbolName)) {
                if (_malloc_zone_malloc == 0) {
                    _malloc_zone_malloc = svcMemory.registerSvc(new ArmHook() {
                        @Override
                        protected HookStatus hook(Unicorn u, Emulator emulator) {
                            Pointer zone = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                            int size = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
                            if (size <= LARGE_THRESHOLD) {
                                Log log = LogFactory.getLog("cn.banny.emulator.ios.malloc");
                                if (log.isDebugEnabled()) {
                                    log.debug("Fake _malloc_zone_malloc zone=" + zone + ", size=" + size);
                                } else if (Dyld.log.isDebugEnabled()) {
                                    Dyld.log.debug("Fake _malloc_zone_malloc zone=" + zone + ", size=" + size);
                                }
                                u.reg_write(ArmConst.UC_ARM_REG_R1, LARGE_THRESHOLD + 1);
                            }
                            return HookStatus.RET(u, old);
                        }
                    }).peer;
                }
                return _malloc_zone_malloc;
            }
            if ("_malloc_zone_calloc".equals(symbolName)) {
                if (_malloc_zone_calloc == 0) {
                    _malloc_zone_calloc = svcMemory.registerSvc(new ArmHook() {
                        @Override
                        protected HookStatus hook(Unicorn u, Emulator emulator) {
                            Pointer zone = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                            int count = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
                            int size = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
                            if (count * size <= LARGE_THRESHOLD) {
                                Log log = LogFactory.getLog("cn.banny.emulator.ios.malloc");
                                if (log.isDebugEnabled()) {
                                    log.debug("Fake _malloc_zone_calloc zone=" + zone + ", count=" + count + ", size=" + size);
                                } else if (Dyld.log.isDebugEnabled()) {
                                    Dyld.log.debug("Fake _malloc_zone_calloc zone=" + zone + ", count=" + count + ", size=" + size);
                                }
                                u.reg_write(ArmConst.UC_ARM_REG_R1, 1);
                                u.reg_write(ArmConst.UC_ARM_REG_R2, LARGE_THRESHOLD + 1);
                            }
                            return HookStatus.RET(u, old);
                        }
                    }).peer;
                }
                return _malloc_zone_calloc;
            }
            if ("_malloc_zone_realloc".equals(symbolName)) {
                if (_malloc_zone_realloc == 0) {
                    _malloc_zone_realloc = svcMemory.registerSvc(new ArmHook() {
                        @Override
                        protected HookStatus hook(Unicorn u, Emulator emulator) {
                            Pointer zone = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                            Pointer pointer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                            int size = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
                            if (size <= LARGE_THRESHOLD) {
                                if (log.isDebugEnabled()) {
                                    log.debug("Fake _malloc_zone_realloc zone=" + zone + ", pointer=" + pointer + ", size=" + size);
                                }
                                u.reg_write(ArmConst.UC_ARM_REG_R2, LARGE_THRESHOLD + 1);
                            }
                            return HookStatus.RET(u, old);
                        }
                    }).peer;
                }
                return _malloc_zone_realloc;
            }
            if ("_malloc_zone_valloc".equals(symbolName)) {
                if (_malloc_zone_valloc == 0) {
                    _malloc_zone_valloc = svcMemory.registerSvc(new ArmHook() {
                        @Override
                        protected HookStatus hook(Unicorn u, Emulator emulator) {
                            Pointer zone = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                            int size = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
                            if (size <= LARGE_THRESHOLD) {
                                Log log = LogFactory.getLog("cn.banny.emulator.ios.malloc");
                                if (log.isDebugEnabled()) {
                                    log.debug("Fake _malloc_zone_valloc zone=" + zone + ", size=" + size);
                                } else if (Dyld.log.isDebugEnabled()) {
                                    Dyld.log.debug("Fake _malloc_zone_valloc zone=" + zone + ", size=" + size);
                                }
                                u.reg_write(ArmConst.UC_ARM_REG_R1, LARGE_THRESHOLD + 1);
                            }
                            return HookStatus.RET(u, old);
                        }
                    }).peer;
                }
                return _malloc_zone_valloc;
            }
            if ("_malloc_zone_memalign".equals(symbolName)) {
                if (_malloc_zone_memalign == 0) {
                    _malloc_zone_memalign = svcMemory.registerSvc(new ArmHook() {
                        @Override
                        protected HookStatus hook(Unicorn u, Emulator emulator) {
                            Pointer zone = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                            int alignment = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
                            int size = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
                            if (size <= LARGE_THRESHOLD) {
                                Log log = LogFactory.getLog("cn.banny.emulator.ios.malloc");
                                if (log.isDebugEnabled()) {
                                    log.debug("Fake _malloc_zone_memalign zone=" + zone + ", alignment=" + alignment + ", size=" + size);
                                } else if (Dyld.log.isDebugEnabled()) {
                                    Dyld.log.debug("Fake _malloc_zone_memalign zone=" + zone + ", alignment=" + alignment + ", size=" + size);
                                }
                                u.reg_write(ArmConst.UC_ARM_REG_R2, LARGE_THRESHOLD + 1);
                            }
                            return HookStatus.RET(u, old);
                        }
                    }).peer;
                }
                return _malloc_zone_memalign;
            }
        } else if ("libsystem_pthread.dylib".equals(libraryName)) {
            if ("_pthread_getname_np".equals(symbolName)) {
                if (_pthread_getname_np == 0) {
                    _pthread_getname_np = svcMemory.registerSvc(new ArmHook() {
                        @Override
                        protected HookStatus hook(Unicorn u, Emulator emulator) {
                            Pointer thread = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                            Pointer threadName = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                            int len = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
                            if (log.isDebugEnabled()) {
                                log.debug("_pthread_getname_np thread=" + thread + ", threadName=" + threadName + ", len=" + len);
                            }
                            byte[] data = Arrays.copyOf(Dyld.this.threadName.getBytes(), len);
                            threadName.write(0, data, 0, data.length);
                            return HookStatus.LR(u, 0);
                        }
                    }).peer;
                }
                return _pthread_getname_np;
            }
        }
        return 0;
    }

//    private long _free;
    private long _realloc, _malloc, _calloc, _valloc;
    private long _malloc_zone_malloc, _malloc_zone_calloc, _malloc_zone_realloc, _malloc_zone_valloc, _malloc_zone_memalign;
    private long _pthread_getname_np;

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

    private String threadName = "main";

    void pthread_setname_np(String threadName) {
        this.threadName = threadName;
        if (log.isDebugEnabled()) {
            log.debug("pthread_setname_np=" + threadName);
        }
    }

}
