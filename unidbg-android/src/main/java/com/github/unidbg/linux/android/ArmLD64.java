package com.github.unidbg.linux.android;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Svc;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.linux.LinuxModule;
import com.github.unidbg.linux.struct.dl_phdr_info64;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.pointer.UnidbgStructure;
import com.github.unidbg.spi.Dlfcn;
import com.github.unidbg.spi.InitFunction;
import com.github.unidbg.unix.struct.DlInfo64;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import net.fornwall.jelf.ElfDynamicStructure;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import unicorn.Arm64Const;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

public class ArmLD64 extends Dlfcn {

    private static final Logger log = LoggerFactory.getLogger(ArmLD64.class);

    private final Backend backend;

    ArmLD64(Backend backend, SvcMemory svcMemory) {
        super(svcMemory);
        this.backend = backend;
    }

    @Override
    public long hook(final SvcMemory svcMemory, String libraryName, String symbolName, long old) {
        if ("libdl.so".equals(libraryName)) {
            if (log.isDebugEnabled()) {
                log.debug("link {}, old=0x{}", symbolName, Long.toHexString(old));
            }
            switch (symbolName) {
                case "dl_iterate_phdr":
                    return svcMemory.registerSvc(new Arm64Svc() {
                        private MemoryBlock block;
                        @Override
                        public UnidbgPointer onRegister(SvcMemory svcMemory, int svcNumber) {
                            try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian)) {
                                KeystoneEncoded encoded = keystone.assemble(Arrays.asList(
                                        "sub sp, sp, #0x10",
                                        "stp x29, x30, [sp]",
                                        "svc #0x" + Integer.toHexString(svcNumber),

                                        "ldr x13, [sp]",
                                        "add sp, sp, #0x8",
                                        "cmp x13, #0",
                                        "b.eq #0x58",
                                        "ldr x0, [sp]",
                                        "add sp, sp, #0x8",
                                        "ldr x1, [sp]",
                                        "add sp, sp, #0x8",
                                        "ldr x2, [sp]",
                                        "add sp, sp, #0x8",
                                        "blr x13",
                                        "cmp w0, #0",
                                        "b.eq #0xc",

                                        "ldr x13, [sp]",
                                        "add sp, sp, #0x8",
                                        "cmp x13, #0",
                                        "b.eq #0x58",
                                        "add sp, sp, #0x18",
                                        "b 0x40",

                                        "mov x8, #0",
                                        "mov x12, #0x" + Integer.toHexString(svcNumber),
                                        "mov x16, #0x" + Integer.toHexString(Svc.POST_CALLBACK_SYSCALL_NUMBER),
                                        "svc #0",

                                        "ldp x29, x30, [sp]",
                                        "add sp, sp, #0x10",
                                        "ret"));
                                byte[] code = encoded.getMachineCode();
                                UnidbgPointer pointer = svcMemory.allocate(code.length, "dl_iterate_phdr");
                                pointer.write(0, code, 0, code.length);
                                if (log.isDebugEnabled()) {
                                    log.debug("dl_iterate_phdr: pointer={}", pointer);
                                }
                                return pointer;
                            }
                        }
                        @Override
                        public long handle(Emulator<?> emulator) {
                            if (block != null) {
                                throw new IllegalStateException();
                            }

                            RegisterContext context = emulator.getContext();
                            UnidbgPointer cb = context.getPointerArg(0);
                            UnidbgPointer data = context.getPointerArg(1);

                            Collection<Module> modules = emulator.getMemory().getLoadedModules();
                            List<LinuxModule> list = new ArrayList<>();
                            for (Module module : modules) {
                                LinuxModule lm = (LinuxModule) module;
                                if (lm.elfFile != null) {
                                    list.add(lm);
                                }
                            }
                            Collections.reverse(list);
                            final int size = UnidbgStructure.calculateSize(dl_phdr_info64.class);
                            block = emulator.getMemory().malloc(size * list.size(), true);
                            UnidbgPointer ptr = block.getPointer();
                            Backend backend = emulator.getBackend();
                            UnidbgPointer sp = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_SP);
                            if (log.isDebugEnabled()) {
                                log.debug("dl_iterate_phdr cb={}, data={}, size={}, sp={}", cb, data, list.size(), sp);
                            }

                            try {
                                sp = sp.share(-8, 0);
                                sp.setLong(0, 0); // NULL-terminated

                                for (LinuxModule module : list) {
                                    dl_phdr_info64 info = new dl_phdr_info64(ptr);
                                    UnidbgPointer dlpi_addr = UnidbgPointer.pointer(emulator, module.virtualBase);
                                    assert dlpi_addr != null;
                                    info.dlpi_addr = dlpi_addr.peer;
                                    ElfDynamicStructure dynamicStructure = module.dynamicStructure;
                                    if (dynamicStructure != null && dynamicStructure.soName > 0 && dynamicStructure.dt_strtab_offset > 0) {
                                        info.dlpi_name = UnidbgPointer.nativeValue(dlpi_addr.share(dynamicStructure.dt_strtab_offset + dynamicStructure.soName));
                                    } else {
                                        info.dlpi_name = UnidbgPointer.nativeValue(module.createPathMemory(svcMemory));
                                    }
                                    info.dlpi_phdr = UnidbgPointer.nativeValue(dlpi_addr.share(module.elfFile.ph_offset));
                                    info.dlpi_phnum = module.elfFile.num_ph;
                                    info.pack();

                                    sp = sp.share(-8, 0);
                                    sp.setPointer(0, data); // data

                                    sp = sp.share(-8, 0);
                                    sp.setLong(0, size); // size

                                    sp = sp.share(-8, 0);
                                    sp.setPointer(0, ptr); // dl_phdr_info

                                    sp = sp.share(-8, 0);
                                    sp.setPointer(0, cb); // callback

                                    ptr = ptr.share(size, 0);
                                }

                                return context.getLongArg(0);
                            } finally {
                                backend.reg_write(Arm64Const.UC_ARM64_REG_SP, sp.peer);
                            }
                        }
                        @Override
                        public void handlePostCallback(Emulator<?> emulator) {
                            super.handlePostCallback(emulator);

                            if (block == null) {
                                throw new IllegalStateException();
                            }
                            block.free();
                            block = null;
                        }
                    }).peer;
                case "dlerror":
                    return svcMemory.registerSvc(new Arm64Svc() {
                        @Override
                        public long handle(Emulator<?> emulator) {
                            return error.peer;
                        }
                    }).peer;
                case "dlclose":
                    return svcMemory.registerSvc(new Arm64Svc() {
                        @Override
                        public long handle(Emulator<?> emulator) {
                            RegisterContext context = emulator.getContext();
                            long handle = context.getLongArg(0);
                            if (log.isDebugEnabled()) {
                                log.debug("dlclose handle=0x{}", Long.toHexString(handle));
                            }
                            return dlclose(emulator.getMemory(), handle);
                        }
                    }).peer;
                case "dlopen":
                    return svcMemory.registerSvc(new Arm64Svc() {
                        @Override
                        public UnidbgPointer onRegister(SvcMemory svcMemory, int svcNumber) {
                            ByteBuffer buffer = ByteBuffer.allocate(56);
                            buffer.order(ByteOrder.LITTLE_ENDIAN);
                            buffer.putInt(0xd10043ff); // "sub sp, sp, #0x10"
                            buffer.putInt(0xa9007bfd); // "stp x29, x30, [sp]"
                            buffer.putInt(Arm64Svc.assembleSvc(svcNumber)); // "svc #0x" + Integer.toHexString(svcNumber)
                            buffer.putInt(0xf94003ed); // "ldr x13, [sp]"
                            buffer.putInt(0x910023ff); // "add sp, sp, #0x8", manipulated stack in dlopen
                            buffer.putInt(0xf10001bf); // "cmp x13, #0"
                            buffer.putInt(0x54000060); // "b.eq #0x24"
                            buffer.putInt(0x10ffff9e); // "adr lr, #-0xf", jump to ldr x13, [sp]
                            buffer.putInt(0xd61f01a0); // "br x13", call init array
                            buffer.putInt(0xf94003e0); // "ldr x0, [sp]", with return address
                            buffer.putInt(0x910023ff); // "add sp, sp, #0x8"
                            buffer.putInt(0xa9407bfd); // "ldp x29, x30, [sp]"
                            buffer.putInt(0x910043ff); // "add sp, sp, #0x10"
                            buffer.putInt(0xd65f03c0); // "ret"
                            byte[] code = buffer.array();
                            UnidbgPointer pointer = svcMemory.allocate(code.length, "dlopen");
                            pointer.write(0, code, 0, code.length);
                            return pointer;
                        }
                        @Override
                        public long handle(Emulator<?> emulator) {
                            RegisterContext context = emulator.getContext();
                            Pointer filename = context.getPointerArg(0);
                            int flags = context.getIntArg(1);
                            if (log.isDebugEnabled()) {
                                log.debug("dlopen filename={}, flags={}, LR={}", filename.getString(0), flags, context.getLRPointer());
                            }
                            return dlopen(emulator.getMemory(), filename.getString(0), emulator);
                        }
                    }).peer;
                case "dladdr":
                    return svcMemory.registerSvc(new Arm64Svc() {
                        @Override
                        public long handle(Emulator<?> emulator) {
                            RegisterContext context = emulator.getContext();
                            long addr = context.getLongArg(0);
                            Pointer info = context.getPointerArg(1);
                            if (log.isDebugEnabled()) {
                                log.debug("dladdr addr=0x{}, info={}, LR={}", Long.toHexString(addr), info, context.getLRPointer());
                            }
                            Module module = emulator.getMemory().findModuleByAddress(addr);
                            if (module == null) {
                                return 0;
                            }

                            Symbol symbol = module.findClosestSymbolByAddress(addr, true);

                            DlInfo64 dlInfo = new DlInfo64(info);
                            dlInfo.dli_fname = UnidbgPointer.nativeValue(module.createPathMemory(svcMemory));
                            dlInfo.dli_fbase = module.base;
                            if (symbol != null) {
                                dlInfo.dli_sname = UnidbgPointer.nativeValue(symbol.createNameMemory(svcMemory));
                                dlInfo.dli_saddr = symbol.getAddress();
                            }
                            dlInfo.pack();
                            return 1;
                        }
                    }).peer;
                case "dlsym":
                    return svcMemory.registerSvc(new Arm64Svc() {
                        @Override
                        public long handle(Emulator<?> emulator) {
                            RegisterContext context = emulator.getContext();
                            long handle = context.getLongArg(0);
                            Pointer symbol = context.getPointerArg(1);
                            if (log.isDebugEnabled()) {
                                log.debug("dlsym handle=0x{}, symbol={}, LR={}", Long.toHexString(handle), symbol.getString(0), context.getLRPointer());
                            }
                            return dlsym(emulator, handle, symbol.getString(0));
                        }
                    }).peer;
                case "dl_unwind_find_exidx":
                    return svcMemory.registerSvc(new Arm64Svc() {
                        @Override
                        public long handle(Emulator<?> emulator) {
                            RegisterContext context = emulator.getContext();
                            Pointer pc = context.getPointerArg(0);
                            Pointer pcount = context.getPointerArg(1);
                            log.info("dl_unwind_find_exidx pc{}, pcount={}", pc, pcount);
                            return 0;
                        }
                    }).peer;
            }
        }
        return 0;
    }

    private long dlopen(Memory memory, String filename, Emulator<?> emulator) {
        UnidbgPointer pointer = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_SP);
        try {
            Module module = memory.dlopen(filename, false);
            pointer = pointer.share(-8, 0); // return value
            if (module == null) {
                pointer.setLong(0, 0);

                pointer = pointer.share(-8, 0); // NULL-terminated
                pointer.setLong(0, 0);

                if (!"libnetd_client.so".equals(filename)) {
                    log.info("dlopen failed: {}", filename);
                } else if(log.isDebugEnabled()) {
                    log.debug("dlopen failed: {}", filename);
                }
                this.error.setString(0, "Resolve library " + filename + " failed");
                return 0;
            } else {
                pointer.setLong(0, module.base);

                pointer = pointer.share(-8, 0); // NULL-terminated
                pointer.setLong(0, 0);

                LinuxModule m = (LinuxModule) module;
                if (m.getUnresolvedSymbol().isEmpty()) {
                    for (InitFunction initFunction : m.initFunctionList) {
                        long address = initFunction.getAddress();
                        if (address == 0) {
                            continue;
                        }
                        if (log.isDebugEnabled()) {
                            log.debug("[{}]PushInitFunction: 0x{}", m.name, Long.toHexString(address));
                        }
                        pointer = pointer.share(-8, 0); // init array
                        pointer.setLong(0, address);
                    }
                    m.initFunctionList.clear();
                }

                return module.base;
            }
        } finally {
            backend.reg_write(Arm64Const.UC_ARM64_REG_SP, pointer.peer);
        }
    }

    private int dlclose(Memory memory, long handle) {
        if (memory.dlclose(handle)) {
            return 0;
        } else {
            this.error.setString(0, "dlclose 0x" + Long.toHexString(handle) + " failed");
            return -1;
        }
    }

}
