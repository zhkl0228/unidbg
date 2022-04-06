package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.Arm64Hook;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.context.EditableArm64RegisterContext;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.ios.struct.DyldUnwindSections;
import com.github.unidbg.memory.Memory;
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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

public class Dyld64 extends Dyld {

    private static final Log log = LogFactory.getLog(Dyld64.class);

    Dyld64(final MachOLoader loader, final SvcMemory svcMemory) {
        super(svcMemory);

        __dyld_register_thread_helpers = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                // the table passed to dyld containing thread helpers
                Pointer helpers = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0);
                if (log.isDebugEnabled()) {
                    log.debug("registerThreadHelpers helpers=" + helpers + ", version=" + helpers.getLong(0));
                }
                return 0;
            }
        });
        __dyld_get_image_slide = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer mh = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0);
                long slide = mh == null ? 0 : computeSlide(emulator, mh.peer);
                log.debug("__dyld_get_image_slide mh=" + mh + ", slide=0x" + Long.toHexString(slide));
                return slide;
            }
        });

        /*
         * _dyld_register_func_for_remove_image registers the specified function to be
         * called when an image is removed (a bundle or a dynamic shared library) from
         * the program.
         */
        __dyld_register_func_for_remove_image = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                Pointer callback = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0);
                if (log.isDebugEnabled()) {
                    log.debug("__dyld_register_func_for_remove_image callback=" + callback);
                }
                return 0;
            }
        });
        __dyld_image_count = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return loader.getLoadedModulesNoVirtual().size();
            }
        });
        __dyld_get_image_name = svcMemory.registerSvc(new Arm64Svc() {
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
        __dyld_get_image_header = svcMemory.registerSvc(new Arm64Svc() {
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
        __dyld_get_image_vmaddr_slide = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                int image_index = emulator.getContext().getIntArg(0);
                Module[] modules = loader.getLoadedModulesNoVirtual().toArray(new Module[0]);
                if (image_index < 0 || image_index >= modules.length) {
                    if (log.isDebugEnabled()) {
                        log.debug("__dyld_get_image_vmaddr_slide index=" + image_index);
                    }
                    return 0;
                }
                MachOModule module = (MachOModule) modules[image_index];
                long slide = computeSlide(emulator, module.machHeader);
                if (log.isDebugEnabled()) {
                    log.debug("__dyld_get_image_vmaddr_slide index=" + image_index + ", slide=0x" + Long.toHexString(slide) + ", module=" + module.name);
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
        __dyld_register_func_for_add_image = svcMemory.registerSvc(new Arm64Svc() {
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
                    log.debug("__dyld_register_func_for_add_image callback=" + callback);
                }

                Pointer pointer = context.getStackPointer();
                try {
                    pointer = pointer.share(-8); // return value
                    pointer.setLong(0, 0);

                    pointer = pointer.share(-8); // NULL-terminated
                    pointer.setLong(0, 0);

                    if (callback != null && !loader.addImageCallbacks.contains(callback)) {
                        loader.addImageCallbacks.add(callback);

                        for (Module md : loader.getLoadedModulesNoVirtual()) {
                            Log log = LogFactory.getLog("com.github.unidbg.ios." + md.name);
                            MachOModule mm = (MachOModule) md;
                            if (mm.executable) {
                                continue;
                            }

                            // (headerType *mh, unsigned long	vmaddr_slide)
                            pointer = pointer.share(-8);
                            pointer.setLong(0, mm.machHeader);
                            pointer = pointer.share(-8);
                            pointer.setLong(0, computeSlide(emulator, mm.machHeader));

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
        __dyld_dyld_register_image_state_change_handler = svcMemory.registerSvc(new Arm64Svc() {
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
                            log.debug("PushImageHandlerFunction: " + handler + ", imageSize=" + imageInfos.length + ", batch=" + batch);
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
        __dyld_image_path_containing_address = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                UnidbgPointer address = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0);
                MachOModule module = (MachOModule) loader.findModuleByAddress(address.peer);
                if (log.isDebugEnabled()) {
                    log.debug("__dyld_image_path_containing_address address=" + address + ", module=" + module);
                }
                if (module != null) {
                    return module.createPathMemory(svcMemory).peer;
                } else {
                    return 0;
                }
            }
        });
        __dyld__NSGetExecutablePath = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                Pointer buf = context.getPointerArg(0);
                int bufSize = context.getIntArg(1);
                if (log.isDebugEnabled()) {
                    log.debug("__dyld__NSGetExecutablePath buf=" + buf + ", bufSize=" + bufSize);
                }
                buf.setString(0, emulator.getProcessName());
                return 0;
            }
        });
        __dyld_fast_stub_entry = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer imageLoaderCache = context.getPointerArg(0);
                long lazyBindingInfoOffset = context.getLongArg(1);
                MachOModule mm = (MachOModule) emulator.getMemory().findModuleByAddress(imageLoaderCache.peer);
                long result = mm.doBindFastLazySymbol(emulator, (int) lazyBindingInfoOffset);
                if (log.isDebugEnabled()) {
                    log.debug("__dyld_fast_stub_entry imageLoaderCache=" + imageLoaderCache + ", lazyBindingInfoOffset=0x" + Long.toHexString(lazyBindingInfoOffset) + ", result=0x" + Long.toHexString(result));
                }
                return result;
            }
        });
        __dyld_find_unwind_sections = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer addr = context.getPointerArg(0);
                Pointer info = context.getPointerArg(1);
                MachOModule module = (MachOModule) emulator.getMemory().findModuleByAddress(addr.peer);
                if (module == null) {
                    log.info("__dyld_find_unwind_sections addr=" + addr + ", info=" + info);
                    return 0;
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("__dyld_find_unwind_sections addr=" + addr + ", info=" + info);
                    }
                    module.getUnwindInfo(new DyldUnwindSections(info));
                    return 1;
                }
            }
        });

        __dyld_dlopen = svcMemory.registerSvc(new Arm64Svc() {
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
                    log.debug("__dyld_dlopen path=" + str + ", mode=0x" + Integer.toHexString(mode));
                }
                return dlopen(emulator, str, mode);
            }
        });

        _os_trace_redirect_func = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                Pointer msg = emulator.getContext().getPointerArg(0);
//                                            Inspector.inspect(msg.getByteArray(0, 16), "_os_trace_redirect_func msg=" + msg);
                System.err.println("_os_trace_redirect_func msg=" + msg.getString(0));
                return 1;
            }
        }).peer;

        sandbox_check = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext ctx = emulator.getContext();
                int pid = ctx.getIntArg(0);
                Pointer operation = ctx.getPointerArg(1);
                int type = ctx.getIntArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("sandbox_check pid=" + pid + ", operation=" + (operation == null ? null : operation.getString(0)) + ", type=" + type);
                }
                return 1;
            }
        }).peer;

        __availability_version_check = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext ctx = emulator.getContext();
                int count = ctx.getIntArg(0);
                Pointer versions = ctx.getPointerArg(1);
                if (log.isDebugEnabled()) {
                    log.debug("_availability_version_check count=" + count + ", versions=" + versions);
                }
                return 1;
            }
        }).peer;

        _dispatch_after = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                long when = context.getLongArg(0);
                Pointer queue = context.getPointerArg(1);
                Pointer block = context.getPointerArg(2);
                System.out.println("dispatch_after when=" + when + ", queue=" + queue + ", block=" + block);
                return 0;
            }
        }).peer;

        _dispatch_async = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                Pointer queue = context.getPointerArg(0);
                Pointer block = context.getPointerArg(1);
                System.out.println("dispatch_async queue=" + queue + ", block=" + block);
                return 0;
            }
        }).peer;

        __dyld_dlsym = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                long handle = context.getLongArg(0);
                Pointer symbol = context.getPointerArg(1);
                if (log.isDebugEnabled()) {
                    log.debug("__dyld_dlsym handle=0x" + Long.toHexString(handle) + ", symbol=" + symbol.getString(0));
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
                if ("dispatch_after".equals(symbolName)) {
                    return _dispatch_after;
                }
                if ("dispatch_async".equals(symbolName)) {
                    return _dispatch_async;
                }
                if ("objc_addLoadImageFunc".equals(symbolName)) {
                    return __dyld_register_func_for_add_image.peer;
                }

                return dlsym(emulator, handle, "_" + symbolName);
            }
        });
        __dyld_dladdr = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                long addr = context.getLongArg(0);
                Pointer info = context.getPointerArg(1);
                if (log.isDebugEnabled()) {
                    log.debug("__dyld_dladdr addr=0x" + Long.toHexString(addr) + ", info=" + info);
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
        __dyld_dlopen_preflight = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                Pointer path = context.getPointerArg(0);
                String pathname = path.getString(0);
                MachOLoader loader = (MachOLoader) emulator.getMemory();
                boolean canLoad = loader.dlopen_preflight(pathname);
                if (log.isDebugEnabled()) {
                    log.debug("dlopen_preflight path=" + pathname + ", canLoad=" + canLoad);
                }
                return canLoad ? 1 : 0;
            }
        });
        __dyld_fork_child = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                if (log.isDebugEnabled()) {
                    log.debug("_dyld_fork_child");
                }
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
    private final Pointer __dyld_dlopen_preflight;
    private final long _os_trace_redirect_func;
    private final long sandbox_check;
    private final long __availability_version_check;
    private final long _dispatch_after, _dispatch_async;

    @Override
    final int _dyld_func_lookup(Emulator<?> emulator, String name, Pointer address) {
        if (log.isDebugEnabled()) {
            log.debug("_dyld_func_lookup name=" + name);
        }
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
            default:
                log.info("_dyld_func_lookup name=" + name + ", address=" + address);
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
                    if ("/usr/sbin/aslmanager".equals(path)) {
                        return 0;
                    }
                    log.info("dlopen failed: " + path);
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
                    log.debug("newLoaded=" + newLoaded + ", contains=" + loaded.contains(module));
                }
                for (Module m : newLoaded) {
                    MachOModule mm = (MachOModule) m;
                    if (mm.hasUnresolvedSymbol()) {
                        continue;
                    }
                    for (InitFunction initFunction : mm.routines) {
                        if (log.isDebugEnabled()) {
                            log.debug("[" + mm.name + "]PushRoutineFunction: 0x" + Long.toHexString(initFunction.getAddress()));
                        }
                        pointer = pointer.share(-8); // routine
                        pointer.setLong(0, initFunction.getAddress());
                    }
                    mm.routines.clear();
                    for (InitFunction initFunction : mm.initFunctionList) {
                        if (log.isDebugEnabled()) {
                            log.debug("[" + mm.name + "]PushModInitFunction: 0x" + Long.toHexString(initFunction.getAddress()));
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

    @Override
    public long hook(SvcMemory svcMemory, String libraryName, String symbolName, final long old) {
        if ("libsystem_c.dylib".equals(libraryName)) {
            if ("_abort".equals(symbolName)) {
                if (_abort == 0) {
                    _abort = svcMemory.registerSvc(new Arm64Svc() {
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
                                log.debug("_asl_open ident=" + (ident == null ? null : ident.getString(0)) + ", facility=" + facility.getString(0) + ", opts=0x" + Integer.toHexString(opts));
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
