package cn.banny.unidbg.linux.android;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.Module;
import cn.banny.unidbg.arm.Arm64Svc;
import cn.banny.unidbg.linux.LinuxModule;
import cn.banny.unidbg.memory.Memory;
import cn.banny.unidbg.memory.SvcMemory;
import cn.banny.unidbg.pointer.UnicornPointer;
import cn.banny.unidbg.spi.Dlfcn;
import cn.banny.unidbg.spi.InitFunction;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;
import unicorn.Unicorn;
import unicorn.UnicornException;

import java.io.IOException;
import java.util.Arrays;

public class ArmLD64 extends Dlfcn {

    private static final Log log = LogFactory.getLog(ArmLD64.class);

    private Unicorn unicorn;

    ArmLD64(Unicorn unicorn, SvcMemory svcMemory) {
        super(svcMemory);
        this.unicorn = unicorn;
    }

    @Override
    public long hook(SvcMemory svcMemory, String libraryName, String symbolName, long old) {
        if ("libdl.so".equals(libraryName)) {
            log.debug("link " + symbolName + ", old=0x" + Long.toHexString(old));
            switch (symbolName) {
                case "dl_iterate_phdr":
                    return svcMemory.registerSvc(new Arm64Svc() {
                        @Override
                        public long handle(Emulator emulator) {
                            Pointer cb = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0);
                            Pointer data = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                            log.info("dl_iterate_phdr cb=" + cb + ", data=" + data);
                            return 0;
                        }
                    }).peer;
                case "dlerror":
                    return svcMemory.registerSvc(new Arm64Svc() {
                        @Override
                        public long handle(Emulator emulator) {
                            return error.peer;
                        }
                    }).peer;
                case "dlclose":
                    return svcMemory.registerSvc(new Arm64Svc() {
                        @Override
                        public long handle(Emulator emulator) {
                            long handle = ((Number) emulator.getUnicorn().reg_read(Arm64Const.UC_ARM64_REG_X0)).longValue();
                            if (log.isDebugEnabled()) {
                                log.debug("dlclose handle=0x" + Long.toHexString(handle));
                            }
                            return dlclose(emulator.getMemory(), handle);
                        }
                    }).peer;
                case "dlopen":
                    return svcMemory.registerSvc(new Arm64Svc() {
                        @Override
                        public UnicornPointer onRegister(SvcMemory svcMemory, int svcNumber) {
                            try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian)) {
                                KeystoneEncoded encoded = keystone.assemble(Arrays.asList(
                                        "sub sp, sp, #0x10",
                                        "stp x29, x30, [sp]",
                                        "svc #0x" + Integer.toHexString(svcNumber),

                                        "ldr x7, [sp]",
                                        "add sp, sp, #0x8", // manipulated stack in dlopen
                                        "cmp x7, #0",
                                        "b.eq #0x24",
                                        "adr lr, #-0xf", // jump to ldr x7, [sp]
                                        "br x7", // call init array

                                        "ldr x0, [sp]", // with return address
                                        "add sp, sp, #0x8",

                                        "ldp x20, x30, [sp]",
                                        "add sp, sp, #0x10",
                                        "ret"));
                                byte[] code = encoded.getMachineCode();
                                UnicornPointer pointer = svcMemory.allocate(code.length);
                                pointer.write(0, code, 0, code.length);
                                return pointer;
                            }
                        }
                        @Override
                        public long handle(Emulator emulator) {
                            Pointer filename = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0);
                            int flags = ((Number) emulator.getUnicorn().reg_read(Arm64Const.UC_ARM64_REG_X1)).intValue();
                            if (log.isDebugEnabled()) {
                                log.debug("dlopen filename=" + filename.getString(0) + ", flags=" + flags);
                            }
                            return dlopen(emulator.getMemory(), filename.getString(0), emulator);
                        }
                    }).peer;
                case "dladdr":
                    return svcMemory.registerSvc(new Arm64Svc() {
                        @Override
                        public long handle(Emulator emulator) {
                            long addr = ((Number) emulator.getUnicorn().reg_read(Arm64Const.UC_ARM64_REG_X0)).longValue();
                            Pointer info = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                            log.info("dladdr addr=0x" + Long.toHexString(addr) + ", info=" + info);
                            throw new UnicornException();
                        }
                    }).peer;
                case "dlsym":
                    return svcMemory.registerSvc(new Arm64Svc() {
                        @Override
                        public long handle(Emulator emulator) {
                            long handle = ((Number) emulator.getUnicorn().reg_read(Arm64Const.UC_ARM64_REG_X0)).longValue();
                            Pointer symbol = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                            if (log.isDebugEnabled()) {
                                log.debug("dlsym handle=0x" + Long.toHexString(handle) + ", symbol=" + symbol.getString(0));
                            }
                            return dlsym(emulator.getMemory(), handle, symbol.getString(0));
                        }
                    }).peer;
                case "dl_unwind_find_exidx":
                    return svcMemory.registerSvc(new Arm64Svc() {
                        @Override
                        public long handle(Emulator emulator) {
                            Pointer pc = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0);
                            Pointer pcount = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                            if (log.isDebugEnabled()) {
                                log.debug("dl_unwind_find_exidx pc" + pc + ", pcount=" + pcount);
                            }
                            return 0;
                        }
                    }).peer;
            }
        }
        return 0;
    }

    private long dlopen(Memory memory, String filename, Emulator emulator) {
        Pointer pointer = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_SP);
        try {
            Module module = memory.dlopen(filename, false);
            if (module == null) {
                pointer = pointer.share(-8); // return value
                pointer.setLong(0, 0);

                pointer = pointer.share(-8); // NULL-terminated
                pointer.setLong(0, 0);

                log.info("dlopen failed: " + filename);
                this.error.setString(0, "Resolve library " + filename + " failed");
                return 0;
            } else {
                pointer = pointer.share(-8); // return value
                pointer.setLong(0, module.base);

                pointer = pointer.share(-8); // NULL-terminated
                pointer.setLong(0, 0);

                for (Module md : memory.getLoadedModules()) {
                    LinuxModule m = (LinuxModule) md;
                    if (!m.getUnresolvedSymbol().isEmpty()) {
                        continue;
                    }
                    for (InitFunction initFunction : m.initFunctionList) {
                        if (log.isDebugEnabled()) {
                            log.debug("[" + m.name + "]PushInitFunction: 0x" + Long.toHexString(initFunction.getAddress()));
                        }
                        pointer = pointer.share(-8); // init array
                        pointer.setLong(0, initFunction.getAddress());
                    }
                    m.initFunctionList.clear();
                }

                return module.base;
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        } finally {
            unicorn.reg_write(Arm64Const.UC_ARM64_REG_SP, ((UnicornPointer) pointer).peer);
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
