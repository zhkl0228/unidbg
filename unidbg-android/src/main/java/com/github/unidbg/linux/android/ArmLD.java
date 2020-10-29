package com.github.unidbg.linux.android;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.ArmSvc;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.linux.LinuxModule;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.spi.Dlfcn;
import com.github.unidbg.spi.InitFunction;
import com.github.unidbg.unix.struct.DlInfo;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.ArmConst;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class ArmLD extends Dlfcn {

    private static final Log log = LogFactory.getLog(ArmLD.class);

    private final Backend backend;

    ArmLD(Backend backend, SvcMemory svcMemory) {
        super(svcMemory);
        this.backend = backend;
    }

    @Override
    public long hook(final SvcMemory svcMemory, String libraryName, String symbolName, long old) {
        if ("libdl.so".equals(libraryName)) {
            if (log.isDebugEnabled()) {
                log.debug("link " + symbolName + ", old=0x" + Long.toHexString(old));
            }
            switch (symbolName) {
                case "dlerror":
                    return svcMemory.registerSvc(new ArmSvc() {
                        @Override
                        public long handle(Emulator<?> emulator) {
                            return error.peer;
                        }
                    }).peer;
                case "dlclose":
                    return svcMemory.registerSvc(new ArmSvc() {
                        @Override
                        public long handle(Emulator<?> emulator) {
                            long handle = emulator.getBackend().reg_read(ArmConst.UC_ARM_REG_R0).intValue() & 0xffffffffL;
                            if (log.isDebugEnabled()) {
                                log.debug("dlclose handle=0x" + Long.toHexString(handle));
                            }
                            return dlclose(emulator.getMemory(), handle);
                        }
                    }).peer;
                case "dlopen":
                    return svcMemory.registerSvc(new ArmSvc() {
                        @Override
                        public UnidbgPointer onRegister(SvcMemory svcMemory, int svcNumber) {
                            ByteBuffer buffer = ByteBuffer.allocate(28);
                            buffer.order(ByteOrder.LITTLE_ENDIAN);
                            buffer.putInt(0xe92d40f0); // push {r4-r7, lr}
                            buffer.putInt(ArmSvc.assembleSvc(svcNumber)); // svc #svcNumber
                            buffer.putInt(0xe49d7004); // pop {r7}
                            buffer.putInt(0xe3570000); // cmp r7, #0
                            buffer.putInt(0x124fe010); // subne lr, pc, #16
                            buffer.putInt(0x112fff17); // bxne r7
                            buffer.putInt(0xe8bd80f1); // pop {r0, r4-r7, pc} with return address
                            byte[] code = buffer.array();
                            UnidbgPointer pointer = svcMemory.allocate(code.length, "dlopen");
                            pointer.write(code);
                            return pointer;
                        }
                        @Override
                        public long handle(Emulator<?> emulator) {
                            Pointer filename = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                            int flags = emulator.getBackend().reg_read(ArmConst.UC_ARM_REG_R1).intValue();
                            if (log.isDebugEnabled()) {
                                log.debug("dlopen filename=" + filename.getString(0) + ", flags=" + flags);
                            }
                            return dlopen(emulator.getMemory(), filename.getString(0), emulator);
                        }
                    }).peer;
                case "dladdr":
                    return svcMemory.registerSvc(new ArmSvc() {
                        @Override
                        public long handle(Emulator<?> emulator) {
                            long addr = emulator.getBackend().reg_read(ArmConst.UC_ARM_REG_R0).intValue() & 0xffffffffL;
                            Pointer info = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                            if (log.isDebugEnabled()) {
                                log.debug("dladdr addr=0x" + Long.toHexString(addr) + ", info=" + info);
                            }
                            Module module = emulator.getMemory().findModuleByAddress(addr);
                            if (module == null) {
                                return 0;
                            }

                            Symbol symbol = module.findNearestSymbolByAddress(addr);

                            DlInfo dlInfo = new DlInfo(info);
                            dlInfo.dli_fname = module.createPathMemory(svcMemory);
                            dlInfo.dli_fbase = UnidbgPointer.pointer(emulator, module.base);
                            if (symbol != null) {
                                dlInfo.dli_sname = symbol.createNameMemory(svcMemory);
                                dlInfo.dli_saddr = UnidbgPointer.pointer(emulator, symbol.getAddress());
                            }
                            dlInfo.pack();
                            return 1;
                        }
                    }).peer;
                case "dlsym":
                    return svcMemory.registerSvc(new ArmSvc() {
                        @Override
                        public long handle(Emulator<?> emulator) {
                            long handle = emulator.getBackend().reg_read(ArmConst.UC_ARM_REG_R0).intValue() & 0xffffffffL;
                            Pointer symbol = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                            if (log.isDebugEnabled()) {
                                log.debug("dlsym handle=0x" + Long.toHexString(handle) + ", symbol=" + symbol.getString(0));
                            }
                            return dlsym(emulator, handle, symbol.getString(0));
                        }
                    }).peer;
                case "dl_unwind_find_exidx":
                    return svcMemory.registerSvc(new ArmSvc() {
                        @Override
                        public long handle(Emulator<?> emulator) {
                            Pointer pc = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                            Pointer pcount = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
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

    private long dlopen(Memory memory, String filename, Emulator<?> emulator) {
        Pointer pointer = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_SP);
        try {
            Module module = memory.dlopen(filename, false);
            pointer = pointer.share(-4); // return value
            if (module == null) {
                pointer.setInt(0, 0);

                pointer = pointer.share(-4); // NULL-terminated
                pointer.setInt(0, 0);

                if (!"libnetd_client.so".equals(filename)) {
                    log.info("dlopen failed: " + filename);
                } else if(log.isDebugEnabled()) {
                    log.debug("dlopen failed: " + filename);
                }
                this.error.setString(0, "Resolve library " + filename + " failed");
                return 0;
            } else {
                pointer.setInt(0, (int) module.base);

                pointer = pointer.share(-4); // NULL-terminated
                pointer.setInt(0, 0);

                for (Module md : memory.getLoadedModules()) {
                    LinuxModule m = (LinuxModule) md;
                    if (!m.getUnresolvedSymbol().isEmpty()) {
                        continue;
                    }
                    for (InitFunction initFunction : m.initFunctionList) {
                        if (log.isDebugEnabled()) {
                            log.debug("[" + m.name + "]PushInitFunction: 0x" + Long.toHexString(initFunction.getAddress()));
                        }
                        pointer = pointer.share(-4); // init array
                        pointer.setInt(0, (int) initFunction.getAddress());
                    }
                    m.initFunctionList.clear();
                }

                return module.base;
            }
        } finally {
            backend.reg_write(ArmConst.UC_ARM_REG_SP, ((UnidbgPointer) pointer).peer);
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
