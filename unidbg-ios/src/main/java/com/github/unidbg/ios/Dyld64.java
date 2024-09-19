package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Svc;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.Arm64Hook;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.context.EditableArm64RegisterContext;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.ios.struct.DyldUnwindSections;
import com.github.unidbg.ios.struct.SystemVersion;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.pointer.UnidbgStructure;
import com.github.unidbg.spi.InitFunction;
import com.github.unidbg.unix.struct.DlInfo64;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import unicorn.Arm64Const;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class Dyld64 extends Dyld {

    private static final Logger log = LoggerFactory.getLogger(Dyld64.class);

    Dyld64(final MachOLoader loader, final SvcMemory svcMemory) {
        super(svcMemory);

        __dyld_register_thread_helpers = svcMemory.registerSvc(new Arm64Svc("dyld_register_thread_helpers") {
            @Override
            public long handle(Emulator<?> emulator) {
                // the table passed to dyld containing thread helpers
                Pointer helpers = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0);
                if (log.isDebugEnabled()) {
                    log.debug("registerThreadHelpers helpers={}, version={}", helpers, helpers.getLong(0));
                }
                return 0;
            }
        });
        __dyld_get_image_slide = svcMemory.registerSvc(new Arm64Svc("dyld_get_image_slide") {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer mh = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0);
                long slide = mh == null ? 0 : MachOModule.computeSlide(emulator, mh.peer);
                log.debug("__dyld_get_image_slide mh={}, slide=0x{}", mh, Long.toHexString(slide));
                return slide;
            }
        });

        /*
         * _dyld_register_func_for_remove_image registers the specified function to be
         * called when an image is removed (a bundle or a dynamic shared library) from
         * the program.
         */
        __dyld_register_func_for_remove_image = svcMemory.registerSvc(new Arm64Svc("dyld_register_func_for_remove_image") {
            @Override
            public long handle(Emulator<?> emulator) {
                Pointer callback = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0);
                if (log.isDebugEnabled()) {
                    log.debug("__dyld_register_func_for_remove_image callback={}", callback);
                }
                return 0;
            }
        });
        __dyld_image_count = svcMemory.registerSvc(new Arm64Svc("dyld_image_count") {
            @Override
            public long handle(Emulator<?> emulator) {
                return loader.getLoadedModulesNoVirtual().size();
            }
        });
        __dyld_get_image_name = svcMemory.registerSvc(new Arm64Svc("dyld_get_image_name") {
            @Override
            public long handle(Emulator<?> emulator) {
                int image_index = emulator.getContext().getIntArg(0);
                Module[] modules = loader.getLoadedModulesNoVirtual().toArray(new Module[0]);
                if (image_index < 0 || image_index >= modules.length) {
                    return 0;
                }
                MachOModule module = (MachOModule) modules[image_index];
                return module.createPathMemory(svcMemory).peer;
            }
        });
        __dyld_get_image_header = svcMemory.registerSvc(new Arm64Svc("dyld_get_image_header") {
            @Override
            public long handle(Emulator<?> emulator) {
                int image_index = emulator.getContext().getIntArg(0);
                Module[] modules = loader.getLoadedModulesNoVirtual().toArray(new Module[0]);
                if (image_index < 0 || image_index >= modules.length) {
                    return 0;
                }
                MachOModule module = (MachOModule) modules[image_index];
                return module.machHeader;
            }
        });
        __dyld_get_image_vmaddr_slide = svcMemory.registerSvc(new Arm64Svc("dyld_get_image_vmaddr_slide") {
            @Override
            public long handle(Emulator<?> emulator) {
                int image_index = emulator.getContext().getIntArg(0);
                Module[] modules = loader.getLoadedModulesNoVirtual().toArray(new Module[0]);
                if (image_index < 0 || image_index >= modules.length) {
                    if (log.isDebugEnabled()) {
                        log.debug("__dyld_get_image_vmaddr_slide index={}", image_index);
                    }
                    return 0;
                }
                MachOModule module = (MachOModule) modules[image_index];
                long slide = module.slide;
                if (log.isDebugEnabled()) {
                    log.debug("__dyld_get_image_vmaddr_slide index={}, slide=0x{}, module={}", image_index, Long.toHexString(slide), module.name);
                }
                return slide;
            }
        });

        /*
         * _dyld_register_func_for_add_image registers the specified function to be
         * called when a new image is added (a bundle or a dynamic shared library) to
         * the program.  When this function is first registered it is called for once
         * for each image that is currently part of the program.
         */
        __dyld_register_func_for_add_image = svcMemory.registerSvc(new Arm64Svc("dyld_register_func_for_add_image") {
            @Override
            public UnidbgPointer onRegister(SvcMemory svcMemory, int svcNumber) {
                try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian)) {
                    KeystoneEncoded encoded = keystone.assemble(Arrays.asList(
                            "sub sp, sp, #0x10",
                            "stp x29, x30, [sp]",
                            "svc #0x" + Integer.toHexString(svcNumber),

                            "ldr x13, [sp]",
                            "add sp, sp, #0x8", // manipulated stack in __dyld_register_func_for_add_image
                            "cmp x13, #0",
                            "b.eq #0x38",
                            "adr lr, #-0xf", // jump to ldr x13, [sp]
                            "bic lr, lr, #0x1",

                            "ldr x0, [sp]",
                            "add sp, sp, #0x8",
                            "ldr x1, [sp]",
                            "add sp, sp, #0x8",
                            "br x13", // call (headerType *mh, unsigned long	vmaddr_slide)

                            "ldr x0, [sp]", // with return address
                            "add sp, sp, #0x8",

                            "ldp x29, x30, [sp]",
                            "add sp, sp, #0x10",
                            "ret"));
                    byte[] code = encoded.getMachineCode();
                    UnidbgPointer pointer = svcMemory.allocate(code.length, "__dyld_register_func_for_add_image");
                    pointer.write(0, code, 0, code.length);
                    return pointer;
                }
            }

            @Override
            public long handle(Emulator<?> emulator) {
                EditableArm64RegisterContext context = emulator.getContext();

                UnidbgPointer callback = context.getPointerArg(0);
                if (log.isDebugEnabled()) {
                    log.debug("__dyld_register_func_for_add_image callback={}", callback);
                }

                Pointer pointer = context.getStackPointer();
                try {
                    pointer = pointer.share(-8); // return value
                    pointer.setLong(0, 0);

                    pointer = pointer.share(-8); // NULL-terminated
                    pointer.setLong(0, 0);

                    if (callback != null && !loader.addImageCallbacks.contains(callback)) {
                        loader.addImageCallbacks.add(callback);

                        List<Module> modules = loader.getLoadedModulesNoVirtual();
                        Collections.reverse(modules);
                        for (Module md : modules) {
                            Logger log = LoggerFactory.getLogger("com.github.unidbg.ios." + md.name);
                            MachOModule mm = (MachOModule) md;
                            if (mm.executable) {
                                continue;
                            }
                            mm.addImageCallSet.add(callback);

                            // (headerType *mh, unsigned long	vmaddr_slide)
                            pointer = pointer.share(-8);
                            pointer.setLong(0, mm.machHeader);
                            pointer = pointer.share(-8);
                            pointer.setLong(0, mm.slide);

                            String msg = "[" + md.name + "]PushAddImageFunction: 0x" + Long.toHexString(mm.machHeader);
                            if (log.isDebugEnabled()) {
                                log.debug(msg);
                            } else if (Dyld64.log.isDebugEnabled()) {
                                Dyld64.log.debug(msg);
                            }
                            pointer = pointer.share(-8); // callback
                            pointer.setPointer(0, callback);
                        }
                    }

                    return 0;
                } finally {
                    context.setStackPointer(pointer);
                }
            }
        });
        __dyld_dyld_register_image_state_change_handler = svcMemory.registerSvc(new Arm64Svc("dyld_dyld_register_image_state_change_handler") {
            @Override
            public UnidbgPointer onRegister(SvcMemory svcMemory, int svcNumber) {
                try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian)) {
                    KeystoneEncoded encoded = keystone.assemble(Arrays.asList(
                            "sub sp, sp, #0x10",
                            "stp x29, x30, [sp]",
                            "svc #0x" + Integer.toHexString(svcNumber),

                            "ldr x13, [sp]",
                            "add sp, sp, #0x8", // manipulated stack in dyld_image_state_change_handler
                            "cmp x13, #0",
                            "b.eq #0x40",
                            "adr lr, #-0xf", // jump to ldr x13, [sp]
                            "bic lr, lr, #0x1",

                            "ldr x0, [sp]",
                            "add sp, sp, #0x8",
                            "ldr x1, [sp]",
                            "add sp, sp, #0x8",
                            "ldr x2, [sp]",
                            "add sp, sp, #0x8",
                            "br x13", // call (*dyld_image_state_change_handler)(enum dyld_image_states state, uint32_t infoCount, const struct dyld_image_info info[])

                            "ldr x0, [sp]", // with return address
                            "add sp, sp, #0x8",

                            "ldp x29, x30, [sp]",
                            "add sp, sp, #0x10",
                            "ret"));
                    byte[] code = encoded.getMachineCode();
                    UnidbgPointer pointer = svcMemory.allocate(code.length, "dyld_image_state_change_handler");
                    pointer.write(0, code, 0, code.length);
                    return pointer;
                }
            }
            @Override
            public long handle(Emulator<?> emulator) {
                EditableArm64RegisterContext context = emulator.getContext();
                int state = context.getIntArg(0);
                int batch = context.getIntArg(1);
                UnidbgPointer handler = context.getPointerArg(2);
                UnidbgStructure[] imageInfos;
                if (batch == 1) {
                    imageInfos = registerImageStateBatchChangeHandler(loader, state, handler, emulator);
                } else {
                    imageInfos = registerImageStateSingleChangeHandler(loader, state, handler, emulator);
                }

                Pointer pointer = context.getStackPointer();
                try {
                    pointer = pointer.share(-8); // return value
                    pointer.setLong(0, 0);

                    pointer = pointer.share(-8); // NULL-terminated
                    pointer.setLong(0, 0);

                    if (handler != null && imageInfos != null) {
                        // (*dyld_image_state_change_handler)(enum dyld_image_states state, uint32_t infoCount, const struct dyld_image_info info[])
                        pointer = pointer.share(-8);
                        pointer.setPointer(0, imageInfos.length == 0 ? null : imageInfos[0].getPointer());
                        pointer = pointer.share(-8);
                        pointer.setLong(0, imageInfos.length);
                        pointer = pointer.share(-8);
                        pointer.setLong(0, state);

                        if (log.isDebugEnabled()) {
                            log.debug("PushImageHandlerFunction: {}, imageSize={}, batch={}", handler, imageInfos.length, batch);
                        }
                        pointer = pointer.share(-8); // handler
                        pointer.setPointer(0, handler);
                    }

                    return 0;
                } finally {
                    context.setStackPointer(pointer);
                }
            }
        });
        __dyld_image_path_containing_address = svcMemory.registerSvc(new Arm64Svc("dyld_image_path_containing_address") {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer address = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0);
                MachOModule module = (MachOModule) loader.findModuleByAddress(address.peer);
                if (log.isDebugEnabled()) {
                    log.debug("__dyld_image_path_containing_address address={}, module={}", address, module);
                }
                if (module != null) {
                    return module.createPathMemory(svcMemory).peer;
                } else {
                    return 0;
                }
            }
        });
        __dyld__NSGetExecutablePath = svcMemory.registerSvc(new Arm64Svc("dyld__NSGetExecutablePath") {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                Pointer buf = context.getPointerArg(0);
                Pointer bufSize = context.getPointerArg(1);
                if (log.isDebugEnabled()) {
                    log.debug("__dyld__NSGetExecutablePath buf={}, bufSize={}", buf, bufSize);
                }
                byte[] str = emulator.getProcessName().getBytes(StandardCharsets.UTF_8);
                byte[] data = Arrays.copyOf(str, str.length + 1);
                if (bufSize.getInt(0) >= data.length) {
                    buf.write(0, data, 0, data.length);
                    return 0;
                }
                bufSize.setInt(0, data.length);
                return -1;
            }
        });
        __dyld_fast_stub_entry = svcMemory.registerSvc(new Arm64Svc("dyld_fast_stub_entry") {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer imageLoaderCache = context.getPointerArg(0);
                long lazyBindingInfoOffset = context.getLongArg(1);
                MachOModule mm = (MachOModule) emulator.getMemory().findModuleByAddress(imageLoaderCache.peer);
                long result = mm.doBindFastLazySymbol(emulator, (int) lazyBindingInfoOffset);
                if (log.isDebugEnabled()) {
                    log.debug("__dyld_fast_stub_entry imageLoaderCache={}, lazyBindingInfoOffset=0x{}, result=0x{}, LR={}", imageLoaderCache, Long.toHexString(lazyBindingInfoOffset), Long.toHexString(result), context.getLRPointer());
                }
                return result;
            }
        });
        __dyld_find_unwind_sections = svcMemory.registerSvc(new Arm64Svc("dyld_find_unwind_sections") {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer addr = context.getPointerArg(0);
                Pointer info = context.getPointerArg(1);
                MachOModule module = (MachOModule) emulator.getMemory().findModuleByAddress(addr.peer);
                if (module == null) {
                    log.info("__dyld_find_unwind_sections addr={}, info={}", addr, info);
                    return 0;
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("__dyld_find_unwind_sections addr={}, info={}", addr, info);
                    }
                    module.getUnwindInfo(new DyldUnwindSections(info));
                    return 1;
                }
            }
        });

        __dyld_dlopen = svcMemory.registerSvc(new Arm64Svc("dyld_dlopen") {
            @Override
            public UnidbgPointer onRegister(SvcMemory svcMemory, int svcNumber) {
                try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian)) {
                    KeystoneEncoded encoded = keystone.assemble(Arrays.asList(
                            "sub sp, sp, #0x10",
                            "stp x29, x30, [sp]",
                            "svc #0x" + Integer.toHexString(svcNumber),

                            "ldr x13, [sp]",
                            "add sp, sp, #0x8", // manipulated stack in dlopen
                            "cmp x13, #0",
                            "b.eq #0x28",
                            "adr lr, #-0xf", // jump to ldr x13, [sp]
                            "bic lr, lr, #0x1",
                            "br x13", // call init array

                            "ldr x0, [sp]", // with return address
                            "add sp, sp, #0x8",

                            "ldp x29, x30, [sp]",
                            "add sp, sp, #0x10",
                            "ret"));
                    byte[] code = encoded.getMachineCode();
                    UnidbgPointer pointer = svcMemory.allocate(code.length, "__dyld_dlopen");
                    pointer.write(0, code, 0, code.length);
                    return pointer;
                }
            }
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                Pointer path = context.getPointerArg(0);
                int mode = context.getIntArg(1);
                String str = path == null ? null : path.getString(0);
                if (log.isDebugEnabled()) {
                    log.debug("__dyld_dlopen path={}, mode=0x{}", str, Integer.toHexString(mode));
                }
                return dlopen(emulator, str, mode);
            }
        });

        _os_trace_redirect_func = svcMemory.registerSvc(new Arm64Svc("os_trace_redirect_func") {
            @Override
            public long handle(Emulator<?> emulator) {
                Pointer msg = emulator.getContext().getPointerArg(0);
                System.err.println("_os_trace_redirect_func msg=" + msg.getString(0));
                return 1;
            }
        }).peer;

        sandbox_check = svcMemory.registerSvc(new Arm64Svc("sandbox_check") {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext ctx = emulator.getContext();
                int pid = ctx.getIntArg(0);
                Pointer operation = ctx.getPointerArg(1);
                int type = ctx.getIntArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("sandbox_check pid={}, operation={}, type={}", pid, operation == null ? null : operation.getString(0), type);
                }
                return 1;
            }
        }).peer;

        __availability_version_check = svcMemory.registerSvc(new Arm64Svc("availability_version_check") {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext ctx = emulator.getContext();
                int count = ctx.getIntArg(0);
                Pointer versions = ctx.getPointerArg(1);
                if (log.isDebugEnabled()) {
                    log.debug("_availability_version_check count={}, versions={}", count, versions);
                }
                return 1;
            }
        }).peer;

        __dyld_dlsym = svcMemory.registerSvc(new Arm64Svc("dyld_dlsym") {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                long handle = context.getLongArg(0);
                Pointer symbol = context.getPointerArg(1);
                if (log.isDebugEnabled()) {
                    log.debug("__dyld_dlsym handle=0x{}, symbol={}", Long.toHexString(handle), symbol.getString(0));
                }

                String symbolName = symbol.getString(0);
                if ((int) handle == Dyld.RTLD_MAIN_ONLY && "_os_trace_redirect_func".equals(symbolName)) {
                    return _os_trace_redirect_func;
                }
                if ("sandbox_check".equals(symbolName)) {
                    return sandbox_check;
                }
                if ("_availability_version_check".equals(symbolName)) {
                    return __availability_version_check;
                }
                if ("objc_addLoadImageFunc".equals(symbolName)) {
                    return __dyld_register_func_for_add_image.peer;
                }

                return dlsym(emulator, handle, "_" + symbolName);
            }
        });
        __dyld_dladdr = svcMemory.registerSvc(new Arm64Svc("dyld_dladdr") {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                long addr = context.getLongArg(0);
                Pointer info = context.getPointerArg(1);
                if (log.isDebugEnabled()) {
                    log.debug("__dyld_dladdr addr=0x{}, info={}", Long.toHexString(addr), info);
                }
                MachOModule module = (MachOModule) loader.findModuleByAddress(addr);
                if (module == null) {
                    return 0;
                }

                Symbol symbol = module.findClosestSymbolByAddress(addr, true);

                DlInfo64 dlInfo = new DlInfo64(info);
                dlInfo.dli_fname = UnidbgPointer.nativeValue(module.createPathMemory(svcMemory));
                dlInfo.dli_fbase = module.machHeader;
                if (symbol != null) {
                    dlInfo.dli_sname = UnidbgPointer.nativeValue(symbol.createNameMemory(svcMemory));
                    dlInfo.dli_saddr = symbol.getAddress();
                }
                dlInfo.pack();
                return 1;
            }
        });
        __dyld_dlclose = svcMemory.registerSvc(new Arm64Svc("dyld_dlclose") {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                long handler = context.getLongArg(0);
                if (log.isDebugEnabled()) {
                    log.debug("__dyld_dlclose handler=0x{}", Long.toHexString(handler));
                }
                return 0;
            }
        });
        __dyld_dlopen_preflight = svcMemory.registerSvc(new Arm64Svc("dyld_dlopen_preflight") {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                Pointer path = context.getPointerArg(0);
                String pathname = path.getString(0);
                MachOLoader loader = (MachOLoader) emulator.getMemory();
                boolean canLoad = loader.dlopen_preflight(pathname);
                if (log.isDebugEnabled()) {
                    log.debug("dlopen_preflight path={}, canLoad={}", pathname, canLoad);
                }
                return canLoad ? 1 : 0;
            }
        });
        __dyld_fork_child = svcMemory.registerSvc(new Arm64Svc("dyld_fork_child") {
            @Override
            public long handle(Emulator<?> emulator) {
                if (log.isDebugEnabled()) {
                    log.debug("_dyld_fork_child");
                }
                return 0;
            }
        });
        __dyld_shared_cache_some_image_overridden = svcMemory.registerSvc(new Arm64Svc("dyld_shared_cache_some_image_overridden") {
            @Override
            public long handle(Emulator<?> emulator) {
                return 0;
            }
        });
    }

    private final Pointer __dyld_image_count;
    private final Pointer __dyld_get_image_name;
    private final Pointer __dyld_get_image_header;
    private final Pointer __dyld_get_image_vmaddr_slide;
    private final Pointer __dyld_get_image_slide;
    private final UnidbgPointer __dyld_register_func_for_add_image;
    private final Pointer __dyld_register_func_for_remove_image;
    private final Pointer __dyld_register_thread_helpers;
    private final Pointer __dyld_dyld_register_image_state_change_handler;
    private final Pointer __dyld_image_path_containing_address;
    private final Pointer __dyld__NSGetExecutablePath;
    private final Pointer __dyld_fast_stub_entry;
    private final Pointer __dyld_find_unwind_sections;
    private final Pointer __dyld_fork_child;

    @Override
    final int _stub_binding_helper() {
        log.info("dyldLazyBinder");
        return 0;
    }

    private final Pointer __dyld_dlopen;
    private final Pointer __dyld_dlsym;
    private final Pointer __dyld_dladdr;
    private final Pointer __dyld_dlclose;
    private final Pointer __dyld_dlopen_preflight;
    private final Pointer __dyld_shared_cache_some_image_overridden;
    private final long _os_trace_redirect_func;
    private final long sandbox_check;
    private final long __availability_version_check;

    @Override
    final int _dyld_func_lookup(Emulator<?> emulator, String name, Pointer address) {
        log.debug("_dyld_func_lookup name={}", name);
        switch (name) {
            case "__dyld_fast_stub_entry": // fastBindLazySymbol
                address.setPointer(0, __dyld_fast_stub_entry);
                return 1;
            case "__dyld__NSGetExecutablePath":
                address.setPointer(0, __dyld__NSGetExecutablePath);
                return 1;
            case "__dyld_get_image_name":
                address.setPointer(0, __dyld_get_image_name);
                return 1;
            case "__dyld_get_image_header":
                address.setPointer(0, __dyld_get_image_header);
                return 1;
            case "__dyld_get_image_slide":
                address.setPointer(0, __dyld_get_image_slide);
                return 1;
            case "__dyld_get_image_vmaddr_slide":
                address.setPointer(0, __dyld_get_image_vmaddr_slide);
                return 1;
            case "__dyld_image_count":
                address.setPointer(0, __dyld_image_count);
                return 1;
            case "__dyld_dlopen_preflight":
                address.setPointer(0, __dyld_dlopen_preflight);
                return 1;
            case "__dyld_dlopen":
                address.setPointer(0, __dyld_dlopen);
                return 1;
            case "__dyld_dladdr":
                address.setPointer(0, __dyld_dladdr);
                return 1;
            case "__dyld_dlclose":
                address.setPointer(0, __dyld_dlclose);
                return 1;
            case "__dyld_dlsym":
                address.setPointer(0, __dyld_dlsym);
                return 1;
            case "__dyld_register_thread_helpers":
                address.setPointer(0, __dyld_register_thread_helpers);
                return 1;
            case "__dyld_image_path_containing_address":
                address.setPointer(0, __dyld_image_path_containing_address);
                return 1;
            case "__dyld_register_func_for_remove_image":
                address.setPointer(0, __dyld_register_func_for_remove_image);
                return 1;
            case "__dyld_find_unwind_sections":
                address.setPointer(0, __dyld_find_unwind_sections);
                return 1;
            case "__dyld_register_func_for_add_image":
                address.setPointer(0, __dyld_register_func_for_add_image);
                return 1;
            case "__dyld_dyld_register_image_state_change_handler":
                address.setPointer(0, __dyld_dyld_register_image_state_change_handler);
                return 1;
            case "__dyld_fork_child":
                address.setPointer(0, __dyld_fork_child);
                return 1;
            case "__dyld_shared_cache_some_image_overridden":
                address.setPointer(0, __dyld_shared_cache_some_image_overridden);
                return 1;
            default:
                log.info("_dyld_func_lookup name={}, address={}", name, address);
                break;
        }
        address.setPointer(0, null);
        return 0;
    }

    private long dlopen(Emulator<?> emulator, String path, int mode) {
        Memory memory = emulator.getMemory();
        EditableArm64RegisterContext context = emulator.getContext();
        Pointer pointer = context.getStackPointer();
        try {
            Collection<Module> loaded = memory.getLoadedModules();
            Module module = path == null ? null : memory.dlopen(path, false);
            if (module == null) {
                int ret;
                if (path == null) {
                    if ((mode & RTLD_FIRST) != 0) {
                        ret = RTLD_MAIN_ONLY;
                    } else {
                        ret = RTLD_DEFAULT;
                    }
                } else {
                    ret = 0;
                }

                pointer = pointer.share(-8); // return value
                pointer.setLong(0, ret);

                pointer = pointer.share(-8); // NULL-terminated
                pointer.setLong(0, 0);

                if (ret == 0) {
                    this.error.setString(0, "Resolve library " + path + " failed");
                    if ("/usr/sbin/aslmanager".equals(path) ||
                            "/System/Library/PrivateFrameworks/Librarian.framework/Librarian".equals(path) ||
                            "/System/Library/PrivateFrameworks/CloudDocs.framework/CloudDocs".equals(path)) {
                        return 0;
                    }
                    log.info("dlopen failed: {}", path);
                    if (log.isDebugEnabled()) {
                        emulator.attach().debug();
                    }
                }
                return 0;
            } else {
                pointer = pointer.share(-8); // return value
                pointer.setLong(0, module.base);

                pointer = pointer.share(-8); // NULL-terminated
                pointer.setLong(0, 0);

                Set<Module> newLoaded = new HashSet<>(memory.getLoadedModules());
                newLoaded.removeAll(loaded);
                if (log.isDebugEnabled()) {
                    log.debug("newLoaded={}, contains={}", newLoaded, loaded.contains(module));
                }
                for (Module m : newLoaded) {
                    MachOModule mm = (MachOModule) m;
                    if (mm.hasUnresolvedSymbol()) {
                        continue;
                    }
                    for (InitFunction initFunction : mm.routines) {
                        if (log.isDebugEnabled()) {
                            log.debug("[{}]PushRoutineFunction: 0x{}", mm.name, Long.toHexString(initFunction.getAddress()));
                        }
                        pointer = pointer.share(-8); // routine
                        pointer.setLong(0, initFunction.getAddress());
                    }
                    mm.routines.clear();
                    for (InitFunction initFunction : mm.initFunctionList) {
                        if (log.isDebugEnabled()) {
                            log.debug("[{}]PushModInitFunction: 0x{}", mm.name, Long.toHexString(initFunction.getAddress()));
                        }
                        pointer = pointer.share(-8); // init array
                        pointer.setLong(0, initFunction.getAddress());
                    }
                    mm.initFunctionList.clear();
                }

                return ((MachOModule) module).machHeader;
            }
        } finally {
            context.setStackPointer(pointer);
        }
    }

    private long _abort;
    private long _asl_open;

    private long _dyld_program_sdk_at_least;
    private long __os_feature_enabled_simple_impl;
    private long __dyld_objc_notify_register;
    private long __dyld_get_shared_cache_range;
    private long __dyld_get_objc_selector;
    private long __dyld_get_prog_image_header;
    private long __dyld_for_each_objc_class;
    private long __dyld_for_each_objc_protocol;
    private long _os_unfair_recursive_lock_lock_with_options;
    private long _os_unfair_recursive_lock_tryunlock4objc;
    private long _os_unfair_recursive_lock_unlock;
    private long _os_unfair_lock_lock_with_options;
    private long _os_unfair_lock_unlock;
    private long _clock_gettime_nsec_np;
    private long _os_variant_allows_internal_security_policies;
    private long _abort_with_reason;
    private long __dyld_is_memory_immutable;

    private long _os_system_version_get_current_version;
    private long _dyld_get_active_platform;
    private long __os_log_set_nscf_formatter;
    private long _dyld_has_inserted_or_interposing_libraries;
    private long __pthread_setspecific_static;
    private long _os_log_shim_enabled;
    private long _os_unfair_lock_assert_owner;
    private long _os_unfair_lock_assert_not_owner;
    private long _os_log_create;
    private long _os_log_type_enabled;
    private long _xpc_copy_entitlement_for_self;
    private long _xpc_connection_activate;
    private long __CFNotificationCenterRegisterDependentNotificationList;
    private long __CFLogvEx3;
    private long _voucher_copy;
    private long _dyld_image_header_containing_address;

    @Override
    public long hook(final SvcMemory svcMemory, String libraryName, String symbolName, final long old) {
        if ("_dyld_image_header_containing_address".equals(symbolName)) {
            if (_dyld_image_header_containing_address == 0) {
                _dyld_image_header_containing_address = svcMemory.registerSvc(new Arm64Svc("dyld_image_header_containing_address") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        RegisterContext context = emulator.getContext();
                        long address = context.getLongArg(0);
                        MachOModule mm = (MachOModule) emulator.getMemory().findModuleByAddress(address);
                        return mm == null ? 0L : mm.machHeader;
                    }
                }).peer;
            }
            return _dyld_image_header_containing_address;
        }
        if ("_voucher_copy".equals(symbolName)) {
            if (_voucher_copy == 0) {
                _voucher_copy = svcMemory.registerSvc(new Arm64Svc("voucher_copy") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        return 0;
                    }
                }).peer;
            }
            return _voucher_copy;
        }
        if ("__CFLogvEx3".equals(symbolName)) {
            if (__CFLogvEx3 == 0) {
                __CFLogvEx3 = svcMemory.registerSvc(new Arm64Svc("CFLogvEx3") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        return 0;
                    }
                }).peer;
            }
            return __CFLogvEx3;
        }
        if ("__CFNotificationCenterRegisterDependentNotificationList".equals(symbolName)) {
            if (__CFNotificationCenterRegisterDependentNotificationList == 0) {
                __CFNotificationCenterRegisterDependentNotificationList = svcMemory.registerSvc(new Arm64Svc("CFNotificationCenterRegisterDependentNotificationList") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        return 0;
                    }
                }).peer;
            }
            return __CFNotificationCenterRegisterDependentNotificationList;
        }
        if ("_xpc_connection_activate".equals(symbolName)) {
            if (_xpc_connection_activate == 0) {
                _xpc_connection_activate = svcMemory.registerSvc(new Arm64Svc("xpc_connection_activate") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        return 0;
                    }
                }).peer;
            }
            return _xpc_connection_activate;
        }
        if ("_xpc_copy_entitlement_for_self".equals(symbolName)) {
            if (_xpc_copy_entitlement_for_self == 0) {
                _xpc_copy_entitlement_for_self = svcMemory.registerSvc(new Arm64Svc("xpc_copy_entitlement_for_self") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        return 0;
                    }
                }).peer;
            }
            return _xpc_copy_entitlement_for_self;
        }
        if ("_os_log_type_enabled".equals(symbolName)) {
            if (_os_log_type_enabled == 0) {
                _os_log_type_enabled = svcMemory.registerSvc(new Arm64Svc("os_log_type_enabled") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        return 0;
                    }
                }).peer;
            }
            return _os_log_type_enabled;
        }
        if ("_os_log_create".equals(symbolName)) {
            if (_os_log_create == 0) {
                _os_log_create = svcMemory.registerSvc(new Arm64Svc("os_log_create") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        return 0;
                    }
                }).peer;
            }
            return _os_log_create;
        }
        if ("_os_unfair_lock_assert_not_owner".equals(symbolName)) {
            if (_os_unfair_lock_assert_not_owner == 0) {
                _os_unfair_lock_assert_not_owner = svcMemory.registerSvc(new Arm64Svc("os_unfair_lock_assert_not_owner") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        return 0;
                    }
                }).peer;
            }
            return _os_unfair_lock_assert_not_owner;
        }
        if ("_os_unfair_lock_assert_owner".equals(symbolName)) {
            if (_os_unfair_lock_assert_owner == 0) {
                _os_unfair_lock_assert_owner= svcMemory.registerSvc(new Arm64Svc("os_unfair_lock_assert_owner") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        return 0;
                    }
                }).peer;
            }
            return _os_unfair_lock_assert_owner;
        }
        if ("_os_log_shim_enabled".equals(symbolName)) {
            if (_os_log_shim_enabled == 0) {
                _os_log_shim_enabled = svcMemory.registerSvc(new Arm64Svc("os_log_shim_enabled") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        return 0;
                    }
                }).peer;
            }
            return _os_log_shim_enabled;
        }
        if ("__pthread_setspecific_static".equals(symbolName)) {
            if (__pthread_setspecific_static == 0) {
                __pthread_setspecific_static = svcMemory.registerSvc(new Arm64Svc("pthread_setspecific_static") {
                    private final long[] tsd = new long[128];
                    @Override
                    public long handle(Emulator<?> emulator) {
                        RegisterContext context = emulator.getContext();
                        int key = context.getIntArg(0);
                        long value = context.getLongArg(1);
                        tsd[key] = value;
                        return 0;
                    }
                }).peer;
            }
            return __pthread_setspecific_static;
        }
        if ("_dyld_has_inserted_or_interposing_libraries".equals(symbolName)) {
            if (_dyld_has_inserted_or_interposing_libraries == 0) {
                _dyld_has_inserted_or_interposing_libraries = svcMemory.registerSvc(new Arm64Svc("dyld_has_inserted_or_interposing_libraries") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        return 0;
                    }
                }).peer;
            }
            return _dyld_has_inserted_or_interposing_libraries;
        }
        if ("__os_log_set_nscf_formatter".equals(symbolName)) {
            if (__os_log_set_nscf_formatter == 0) {
                __os_log_set_nscf_formatter = svcMemory.registerSvc(new Arm64Svc("os_log_set_nscf_formatter") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        return 0;
                    }
                }).peer;
            }
            return __os_log_set_nscf_formatter;
        }
        if ("_dyld_get_active_platform".equals(symbolName)) {
            if (_dyld_get_active_platform == 0) {
                _dyld_get_active_platform = svcMemory.registerSvc(new Arm64Svc("dyld_get_active_platform") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        return 2; // PLATFORM_IOS
                    }
                }).peer;
            }
            return _dyld_get_active_platform;
        }
        if ("_os_unfair_lock_unlock".equals(symbolName)) {
            if (_os_unfair_lock_unlock == 0) {
                _os_unfair_lock_unlock = svcMemory.registerSvc(new Arm64Svc("os_unfair_lock_unlock") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        RegisterContext context = emulator.getContext();
                        Pointer lock = context.getPointerArg(0);
                        if (log.isDebugEnabled()) {
                            log.debug("_os_unfair_lock_unlock lock={}, LR={}", lock, context.getLRPointer());
                        }
                        return 0;
                    }
                }).peer;
            }
            return _os_unfair_lock_unlock;
        }
        if ("_os_unfair_lock_lock_with_options".equals(symbolName)) {
            if (_os_unfair_lock_lock_with_options == 0) {
                _os_unfair_lock_lock_with_options = svcMemory.registerSvc(new Arm64Svc("os_unfair_lock_lock_with_options") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        RegisterContext context = emulator.getContext();
                        Pointer lock = context.getPointerArg(0);
                        int options = context.getIntArg(1);
                        if (log.isDebugEnabled()) {
                            log.debug("_os_unfair_lock_lock_with_options lock={}, options=0x{}", lock, Integer.toHexString(options));
                        }
                        return 0;
                    }
                }).peer;
            }
            return _os_unfair_lock_lock_with_options;
        }
        if ("_dyld_program_sdk_at_least".equals(symbolName)) {
            if (_dyld_program_sdk_at_least == 0) {
                _dyld_program_sdk_at_least = svcMemory.registerSvc(new Arm64Svc("_dyld_program_sdk_at_least") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        RegisterContext context = emulator.getContext();
                        long version = context.getLongArg(0);
                        if (log.isDebugEnabled()) {
                            log.debug("_dyld_program_sdk_at_least version=0x{}", Long.toHexString(version));
                        }
                        return 0;
                    }
                }).peer;
            }
            return _dyld_program_sdk_at_least;
        }
        if ("libswiftCore.dylib".equals(libraryName)) {
            if ("_os_system_version_get_current_version".equals(symbolName)) {
                if (_os_system_version_get_current_version == 0) {
                    _os_system_version_get_current_version = svcMemory.registerSvc(new Arm64Svc("os_system_version_get_current_version") {
                        @Override
                        public long handle(Emulator<?> emulator) {
                            RegisterContext context = emulator.getContext();
                            Pointer pointer = context.getPointerArg(0);
                            // 7.1.0
                            SystemVersion systemVersion = new SystemVersion(pointer);
                            systemVersion.major = 7;
                            systemVersion.minor = 1;
                            systemVersion.patch = 0;
                            systemVersion.pack();
                            return 0;
                        }
                    }).peer;
                }
                return _os_system_version_get_current_version;
            }
        }
        if ("__dyld_is_memory_immutable".equals(symbolName)) {
            if (__dyld_is_memory_immutable == 0) {
                __dyld_is_memory_immutable = svcMemory.registerSvc(new Arm64Svc("dyld_is_memory_immutable") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        RegisterContext context = emulator.getContext();
                        UnidbgPointer addr = context.getPointerArg(0);
                        long length = context.getIntArg(1);
                        if (log.isDebugEnabled()) {
                            log.debug("dyld_is_memory_immutable addr={}, length={}", addr, length);
                        }
                        return 0;
                    }
                }).peer;
            }
            return __dyld_is_memory_immutable;
        }
        if ("libobjc.A.dylib".equals(libraryName)) {
            if ("_abort_with_reason".equals(symbolName)) {
                if (_abort_with_reason == 0) {
                    _abort_with_reason = svcMemory.registerSvc(new Arm64Svc("abort_with_reason") {
                        @Override
                        public long handle(Emulator<?> emulator) {
                            RegisterContext context = emulator.getContext();
                            int reason_namespace = context.getIntArg(0);
                            long reason_code = context.getLongArg(1);
                            Pointer reason_string = context.getPointerArg(2);
                            long reason_flags = context.getLongArg(3);
                            System.err.println("abort_with_reason namespace=" + reason_namespace + ", code=" + reason_code + ", string=" + reason_string.getString(0) + ", flags=0x" + Long.toHexString(reason_flags));
                            emulator.attach().debug();
                            return 0;
                        }
                    }).peer;
                }
                return _abort_with_reason;
            }
            if ("__dyld_for_each_objc_protocol".equals(symbolName)) {
                if (__dyld_for_each_objc_protocol == 0) {
                    __dyld_for_each_objc_protocol = svcMemory.registerSvc(new Arm64Svc("dyld_for_each_objc_protocol") {
                        @Override
                        public long handle(Emulator<?> emulator) {
                            RegisterContext context = emulator.getContext();
                            Pointer protocolName = context.getPointerArg(0);
                            Pointer callback = context.getPointerArg(1);
                            if (log.isDebugEnabled()) {
                                log.debug("dyld_for_each_objc_protocol protocolName={}, callback={}", protocolName.getString(0), callback);
                            }
                            return 0;
                        }
                    }).peer;
                }
                return __dyld_for_each_objc_protocol;
            }
            if ("__dyld_for_each_objc_class".equals(symbolName)) {
                if (__dyld_for_each_objc_class == 0) {
                    __dyld_for_each_objc_class = svcMemory.registerSvc(new Arm64Svc("dyld_for_each_objc_class") {
                        @Override
                        public long handle(Emulator<?> emulator) {
                            RegisterContext context = emulator.getContext();
                            Pointer className = context.getPointerArg(0);
                            Pointer callback = context.getPointerArg(1);
                            if (log.isDebugEnabled()) {
                                log.debug("dyld_for_each_objc_class className={}, callback={}", className.getString(0), callback);
                            }
                            return 0;
                        }
                    }).peer;
                }
                return __dyld_for_each_objc_class;
            }
            if ("_os_variant_allows_internal_security_policies".equals(symbolName)) {
                if (_os_variant_allows_internal_security_policies == 0) {
                    _os_variant_allows_internal_security_policies = svcMemory.registerSvc(new Arm64Svc("os_variant_allows_internal_security_policies") {
                        @Override
                        public long handle(Emulator<?> emulator) {
                            RegisterContext context = emulator.getContext();
                            Pointer subsystem = context.getPointerArg(0);
                            if (log.isDebugEnabled()) {
                                log.debug("_os_variant_allows_internal_security_policies subsystem={}", subsystem.getString(0));
                            }
                            return 0;
                        }
                    }).peer;
                }
                return _os_variant_allows_internal_security_policies;
            }
            if ("__dyld_get_prog_image_header".equals(symbolName)) {
                if (__dyld_get_prog_image_header == 0) {
                    __dyld_get_prog_image_header = svcMemory.registerSvc(new Arm64Svc("dyld_get_prog_image_header") {
                        @Override
                        public long handle(Emulator<?> emulator) {
                            MachOLoader loader = (MachOLoader) emulator.getMemory();
                            MachOModule mm = (MachOModule) loader.getExecutableModule();
                            if (mm == null) {
                                throw new IllegalStateException();
                            }
                            return mm.machHeader;
                        }
                    }).peer;
                }
                return __dyld_get_prog_image_header;
            }
            if ("__dyld_get_objc_selector".equals(symbolName)) {
                if (__dyld_get_objc_selector == 0) {
                    __dyld_get_objc_selector = svcMemory.registerSvc(new Arm64Svc("dyld_get_objc_selector") {
                        @Override
                        public long handle(Emulator<?> emulator) {
                            EditableArm64RegisterContext context = emulator.getContext();
                            long selName = context.getLongArg(0);
                            if (log.isDebugEnabled()) {
                                log.debug("dyld_get_objc_selector selName=0x{}", Long.toHexString(selName));
                            }
                            return 0;
                        }
                    }).peer;
                }
                return __dyld_get_objc_selector;
            }
            if ("__dyld_get_shared_cache_range".equals(symbolName)) {
                if (__dyld_get_shared_cache_range == 0) {
                    __dyld_get_shared_cache_range = svcMemory.registerSvc(new Arm64Svc("dyld_get_shared_cache_range") {
                        @Override
                        public long handle(Emulator<?> emulator) {
                            return 0;
                        }
                    }).peer;
                }
                return __dyld_get_shared_cache_range;
            }
            /*
             * Note: only for use by objc runtime
             * Register handlers to be called when objc images are mapped, unmapped, and initialized.
             * Dyld will call back the "mapped" function with an array of images that contain an objc-image-info section.
             * Those images that are dylibs will have the ref-counts automatically bumped, so objc will no longer need to
             * call dlopen() on them to keep them from being unloaded.  During the call to _dyld_objc_notify_register(),
             * dyld will call the "mapped" function with already loaded objc images.  During any later dlopen() call,
             * dyld will also call the "mapped" function.  Dyld will call the "init" function when dyld would be called
             * initializers in that image.  This is when objc calls any +load methods in that image.
             */
            if ("__dyld_objc_notify_register".equals(symbolName)) {
                if (__dyld_objc_notify_register == 0) {
                    __dyld_objc_notify_register = svcMemory.registerSvc(new Arm64Svc("dyld_objc_notify_register") {
                        private MemoryBlock block;
                        private final List<MachOModule> list = new ArrayList<>(10);
                        private final boolean objcNotifyInit = false;
                        @Override
                        public UnidbgPointer onRegister(SvcMemory svcMemory, int svcNumber) {
                            try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian)) {
                                KeystoneEncoded encoded = keystone.assemble(Arrays.asList(
                                        "sub sp, sp, #0x10",
                                        "stp x29, x30, [sp]",
                                        "svc #0x" + Integer.toHexString(svcNumber),

                                        "blr x13", // call (*_dyld_objc_notify_mapped)(unsigned count, const char* const paths[], const struct mach_header* const mh[]);

                                        "ldr x13, [sp]",
                                        "add sp, sp, #0x8", // manipulated stack in dyld_objc_notify_register
                                        "cmp x13, #0",
                                        "b.eq #0x30",
                                        "adr lr, #-0x10", // jump to ldr x13, [sp]
                                        "ldp x0, x1, [sp]",
                                        "add sp, sp, #0x10",
                                        "br x13", // call _dyld_objc_notify_init

                                        "mov x8, #0",
                                        "mov x12, #0x" + Integer.toHexString(svcNumber),
                                        "mov x16, #0x" + Integer.toHexString(Svc.POST_CALLBACK_SYSCALL_NUMBER),
                                        "svc #0",

                                        "ldp x29, x30, [sp]",
                                        "add sp, sp, #0x10",
                                        "ret"));
                                byte[] code = encoded.getMachineCode();
                                UnidbgPointer pointer = svcMemory.allocate(code.length, "dyld_objc_notify_register");
                                pointer.write(0, code, 0, code.length);
                                if (log.isDebugEnabled()) {
                                    log.debug("_dyld_objc_notify_register pointer={}", pointer);
                                }
                                return pointer;
                            }
                        }
                        @Override
                        public long handle(Emulator<?> emulator) {
                            if (block != null) {
                                throw new IllegalStateException();
                            }

                            EditableArm64RegisterContext context = emulator.getContext();
                            UnidbgPointer mapped = context.getPointerArg(0);
                            UnidbgPointer init = context.getPointerArg(1);
                            UnidbgPointer unmapped = context.getPointerArg(2);
                            if (mapped == null || init == null) {
                                throw new IllegalStateException();
                            }

                            if (log.isDebugEnabled()) {
                                log.debug("__dyld_objc_notify_register mapped={}, init={}, unmapped={}", mapped, init, unmapped);
                            }
                            MachOLoader loader = (MachOLoader) emulator.getMemory();
                            loader._objcNotifyMapped = mapped;
                            loader._objcNotifyInit = init;
                            for (MachOModule mm : loader.modules.values()) {
                                if (!mm.isVirtual()) {
                                    list.add(mm);
                                }
                            }
                            Collections.reverse(list);

                            Pointer pointer = context.getStackPointer();
                            try {
                                pointer = pointer.share(-8); // NULL-terminated
                                pointer.setLong(0, 0);

                                if (objcNotifyInit) {
                                    for (MachOModule mm : list) {
                                        // typedef void (*_dyld_objc_notify_init)(const char* path, const struct mach_header* mh);
                                        pointer = pointer.share(-8);
                                        pointer.setLong(0, mm.machHeader);
                                        pointer = pointer.share(-8);
                                        pointer.setPointer(0, mm.createPathMemory(svcMemory));
                                        pointer = pointer.share(-8); // _dyld_objc_notify_init
                                        pointer.setPointer(0, init);
                                    }
                                }
                            } finally {
                                context.setStackPointer(pointer);
                            }

                            block = emulator.getMemory().malloc(16 * list.size(), true);
                            UnidbgPointer paths = block.getPointer();
                            UnidbgPointer mh = paths.share(8L * list.size(), 8L * list.size());
                            for (int i = 0; i < list.size(); i++) {
                                MachOModule mm = list.get(i);
                                paths.setPointer(i * 8L, mm.createPathMemory(svcMemory));
                                mh.setLong(i * 8L, mm.machHeader);
                            }

                            context.setXLong(1, UnidbgPointer.nativeValue(paths));
                            context.setXLong(2, UnidbgPointer.nativeValue(mh));
                            context.setXLong(13, UnidbgPointer.nativeValue(mapped));
                            return list.size();
                        }
                        @Override
                        public void handlePostCallback(Emulator<?> emulator) {
                            super.handlePostCallback(emulator);

                            if (block == null) {
                                throw new IllegalStateException();
                            }
                            for (MachOModule mm : list) {
                                mm.objcNotifyMapped = true;
                                mm.objcNotifyInit = objcNotifyInit;
                            }
                            list.clear();
                            block.free();
                            block = null;
                        }
                    }).peer;
                }
                return __dyld_objc_notify_register;
            }
            if ("_clock_gettime_nsec_np".equals(symbolName)) {
                if (_clock_gettime_nsec_np == 0) {
                    _clock_gettime_nsec_np = svcMemory.registerSvc(new Arm64Svc("clock_gettime_nsec_np") {
                        @Override
                        public long handle(Emulator<?> emulator) {
                            RegisterContext context = emulator.getContext();
                            int clock_id = context.getIntArg(0);
                            switch (clock_id) {
                                case DarwinSyscall.CLOCK_MONOTONIC_RAW:
                                    return System.nanoTime() - DarwinSyscall.nanoTime;
                                case DarwinSyscall.CLOCK_MONOTONIC:
                                default:
                                    throw new UnsupportedOperationException("clock_id=" + clock_id);
                            }
                        }
                    }).peer;
                }
                return _clock_gettime_nsec_np;
            }
            if ("_os_unfair_recursive_lock_tryunlock4objc".equals(symbolName)) {
                if (_os_unfair_recursive_lock_tryunlock4objc == 0) {
                    _os_unfair_recursive_lock_tryunlock4objc = svcMemory.registerSvc(new Arm64Svc("os_unfair_recursive_lock_tryunlock4objc") {
                        @Override
                        public long handle(Emulator<?> emulator) {
                            if (log.isDebugEnabled()) {
                                log.debug("os_unfair_recursive_lock_tryunlock4objc");
                            }
                            return 1;
                        }
                    }).peer;
                }
                return _os_unfair_recursive_lock_tryunlock4objc;
            }
            if ("_os_unfair_recursive_lock_lock_with_options".equals(symbolName)) {
                if (_os_unfair_recursive_lock_lock_with_options == 0) {
                    _os_unfair_recursive_lock_lock_with_options = svcMemory.registerSvc(new Arm64Svc("os_unfair_recursive_lock_lock_with_options") {
                        @Override
                        public long handle(Emulator<?> emulator) {
                            if (log.isDebugEnabled()) {
                                log.debug("os_unfair_recursive_lock_lock_with_options");
                            }
                            return 0;
                        }
                    }).peer;
                }
                return _os_unfair_recursive_lock_lock_with_options;
            }
            if ("_os_unfair_recursive_lock_unlock".equals(symbolName)) {
                if (_os_unfair_recursive_lock_unlock == 0) {
                    _os_unfair_recursive_lock_unlock = svcMemory.registerSvc(new Arm64Svc("os_unfair_recursive_lock_unlock") {
                        @Override
                        public long handle(Emulator<?> emulator) {
                            if (log.isDebugEnabled()) {
                                log.debug("os_unfair_recursive_lock_unlock");
                            }
                            return 0;
                        }
                    }).peer;
                }
                return _os_unfair_recursive_lock_unlock;
            }
            if ("__os_feature_enabled_simple_impl".equals(symbolName)) {
                if (__os_feature_enabled_simple_impl == 0) {
                    __os_feature_enabled_simple_impl = svcMemory.registerSvc(new Arm64Svc("os_feature_enabled_simple_impl") {
                        @Override
                        public long handle(Emulator<?> emulator) {
                            RegisterContext context = emulator.getContext();
                            Pointer domain = context.getPointerArg(0);
                            Pointer feature = context.getPointerArg(1);
                            int status = context.getIntArg(2);
                            if (log.isDebugEnabled()) {
                                log.debug("__os_feature_enabled_simple_impl domain={}, feature={}, status={}", domain.getString(0), feature.getString(0), status);
                            }
                            return 0;
                        }
                    }).peer;
                }
                return __os_feature_enabled_simple_impl;
            }
        }
        if ("libsystem_c.dylib".equals(libraryName)) {
            if ("_abort".equals(symbolName)) {
                if (_abort == 0) {
                    _abort = svcMemory.registerSvc(new Arm64Svc("abort") {
                        @Override
                        public long handle(Emulator<?> emulator) {
                            System.err.println("abort");
                            emulator.attach().debug();
                            emulator.getBackend().reg_write(Arm64Const.UC_ARM64_REG_LR, emulator.getReturnAddress());
                            return 0;
                        }
                    }).peer;
                }
                return _abort;
            }
        } else if ("libsystem_asl.dylib".equals(libraryName)) {
            if ("_asl_open".equals(symbolName)) {
                if (_asl_open == 0) {
                    _asl_open = svcMemory.registerSvc(new Arm64Hook() {
                        @Override
                        protected HookStatus hook(Emulator<?> emulator) {
                            EditableArm64RegisterContext context = emulator.getContext();
                            Pointer ident = context.getPointerArg(0);
                            Pointer facility = context.getPointerArg(1);
                            int opts = context.getIntArg(2);
                            if (log.isDebugEnabled()) {
                                log.debug("_asl_open ident={}, facility={}, opts=0x{}", ident == null ? null : ident.getString(0), facility.getString(0), Integer.toHexString(opts));
                            }
                            context.setXLong(2, opts | ASL_OPT_STDERR);
                            return HookStatus.RET(emulator, old);
                        }
                    }).peer;
                }
                return _asl_open;
            }
        }
        return 0;
    }

}
