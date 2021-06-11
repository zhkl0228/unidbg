package com.github.unidbg.ios.ipa;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.ArmSvc;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.hook.HookListener;
import com.github.unidbg.ios.struct.DispatchSourceType;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.Arrays;

public class SymbolResolver implements HookListener {

    private static final Log log = LogFactory.getLog(SymbolResolver.class);

    private final Emulator<DarwinFileIO> emulator;
    private UnidbgPointer _os_unfair_lock_lock, _os_unfair_lock_unlock;
    private UnidbgPointer _objc_readClassPair;
    private UnidbgPointer _objc_unsafeClaimAutoreleasedReturnValue;
    private UnidbgPointer __tlv_bootstrap;

    private UnidbgPointer __dispatch_source_type_memorypressure;
    private UnidbgPointer dispatch_source_type_memorypressure_init;
    private UnidbgPointer ___chkstk_darwin;
    private UnidbgPointer _clock_gettime;

    public SymbolResolver(Emulator<DarwinFileIO> emulator) {
        this.emulator = emulator;
    }

    private final long nanoTime = System.nanoTime();

    private static final int CLOCK_REALTIME = 0;
    private static final int CLOCK_MONOTONIC_RAW = 4;
    private static final int CLOCK_MONOTONIC = 6;

    @Override
    public long hook(final SvcMemory svcMemory, String libraryName, String symbolName, long old) {
        /*if (symbolName.contains("chkstk_darwin")) {
            System.out.println("libraryName=" + libraryName + ", symbolName=" + symbolName + ", old=0x" + Long.toHexString(old));
        }*/
        if ("_clock_gettime".equals(symbolName) && emulator.is64Bit()) {
            if (_clock_gettime == null) {
                _clock_gettime = svcMemory.registerSvc(new Arm64Svc() {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        RegisterContext context = emulator.getContext();
                        int clk_id = context.getIntArg(0);
                        Pointer tp = context.getPointerArg(1);
                        long offset = clk_id == CLOCK_REALTIME ? System.currentTimeMillis() * 1000000L : System.nanoTime() - nanoTime;
                        long tv_sec = offset / 1000000000L;
                        long tv_nsec = offset % 1000000000L;
                        if (log.isDebugEnabled()) {
                            log.debug("clock_gettime clk_id=" + clk_id + ", tp=" + tp + ", offset=" + offset + ", tv_sec=" + tv_sec + ", tv_nsec=" + tv_nsec);
                        }
                        switch (clk_id) {
                            case CLOCK_REALTIME:
                            case CLOCK_MONOTONIC:
                            case CLOCK_MONOTONIC_RAW:
                                tp.setLong(0, tv_sec);
                                tp.setLong(8, tv_nsec);
                                return 0;
                        }
                        throw new UnsupportedOperationException("clk_id=" + clk_id);
                    }
                });
            }
            return _clock_gettime.peer;
        }
        if ("___chkstk_darwin".equals(symbolName) && emulator.is64Bit()) {
            if (___chkstk_darwin == null) {
                ___chkstk_darwin = svcMemory.registerSvc(new Arm64Svc() {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        return emulator.getContext().getLongArg(0);
                    }
                });
            }
            return ___chkstk_darwin.peer;
        }
        if ("__dispatch_source_type_memorypressure".equals(symbolName) && emulator.is64Bit()) {
            if (dispatch_source_type_memorypressure_init == null) {
                dispatch_source_type_memorypressure_init = svcMemory.registerSvc(new Arm64Svc() {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        System.out.println("dispatch_source_type_memorypressure_init");
                        return 0;
                    }
                });
            }
            if (__dispatch_source_type_memorypressure == null) {
                final short EVFILT_MEMORYSTATUS = (-14); /* Memorystatus events */
                final short EV_DISPATCH = 0x0080; /* disable event after reporting */
                final int NOTE_MEMORYSTATUS_PRESSURE_NORMAL = 0x00000001; /* system memory pressure has returned to normal */
                final int NOTE_MEMORYSTATUS_PRESSURE_WARN = 0x00000002; /* system memory pressure has changed to the warning state */
                final int NOTE_MEMORYSTATUS_PRESSURE_CRITICAL = 0x00000004; /* system memory pressure has changed to the critical state */
                __dispatch_source_type_memorypressure = svcMemory.allocate(128, "__dispatch_source_type_memorypressure");
                DispatchSourceType dispatchSourceType = new DispatchSourceType(__dispatch_source_type_memorypressure);
                dispatchSourceType.ke.filter = EVFILT_MEMORYSTATUS;
                dispatchSourceType.ke.flags = EV_DISPATCH;
                dispatchSourceType.mask = NOTE_MEMORYSTATUS_PRESSURE_NORMAL | NOTE_MEMORYSTATUS_PRESSURE_WARN | NOTE_MEMORYSTATUS_PRESSURE_CRITICAL;
                dispatchSourceType.init = dispatch_source_type_memorypressure_init.peer;
                dispatchSourceType.pack();
            }
            return __dispatch_source_type_memorypressure.peer;
        }
        if ("_objc_unsafeClaimAutoreleasedReturnValue".equals(symbolName)) {
            if (_objc_unsafeClaimAutoreleasedReturnValue == null) {
                _objc_unsafeClaimAutoreleasedReturnValue = svcMemory.registerSvc(emulator.is64Bit() ? new Arm64Svc() {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        RegisterContext context = emulator.getContext();
                        return context.getLongArg(0);
                    }
                } : new ArmSvc() {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        RegisterContext context = emulator.getContext();
                        return context.getIntArg(0);
                    }
                });
            }
            return _objc_unsafeClaimAutoreleasedReturnValue.peer;
        }
        if ("_os_unfair_lock_lock".equals(symbolName)) {
            if (_os_unfair_lock_lock == null) {
                _os_unfair_lock_lock = svcMemory.registerSvc(emulator.is64Bit() ? new Arm64Svc() {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        return 0;
                    }
                } : new ArmSvc() {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        return 0;
                    }
                });
            }
            return _os_unfair_lock_lock.peer;
        }
        if ("_os_unfair_lock_unlock".equals(symbolName)) {
            if (_os_unfair_lock_unlock == null) {
                _os_unfair_lock_unlock = svcMemory.registerSvc(emulator.is64Bit() ? new Arm64Svc() {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        return 0;
                    }
                } : new ArmSvc() {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        return 0;
                    }
                });
            }
            return _os_unfair_lock_unlock.peer;
        }
        if ("__tlv_bootstrap".equals(symbolName)) {
            if (__tlv_bootstrap == null) {
                __tlv_bootstrap = svcMemory.registerSvc(emulator.is64Bit() ? new Arm64Svc() {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        RegisterContext context = emulator.getContext();
                        UnidbgPointer self = context.getPointerArg(0);
                        UnidbgPointer var = self.getPointer(8);
                        if (var == null) {
                            long size = self.getLong(16);
                            MemoryBlock block = emulator.getMemory().malloc((int) size, true);
                            var = block.getPointer();
                            self.setPointer(8, var);
                        }
                        return var.peer;
                    }
                } : new ArmSvc() {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        throw new UnsupportedOperationException();
                    }
                });
            }
            return __tlv_bootstrap.peer;
        }
        if ("_objc_readClassPair".equals(symbolName)) {
            if (_objc_readClassPair == null) {
                _objc_readClassPair = svcMemory.registerSvc(emulator.is64Bit() ? new Arm64Svc() {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        throw new UnsupportedOperationException();
                    }
                    @Override
                    public UnidbgPointer onRegister(SvcMemory svcMemory, int svcNumber) {
                        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian)) {
                            KeystoneEncoded encoded = keystone.assemble(Arrays.asList(
                                    "nop",
                                    "ret"));
                            byte[] code = encoded.getMachineCode();
                            UnidbgPointer pointer = svcMemory.allocate(code.length, "objc_readClassPair");
                            pointer.write(0, code, 0, code.length);
                            return pointer;
                        }
                    }
                } : new ArmSvc() {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        throw new UnsupportedOperationException();
                    }
                    @Override
                    public UnidbgPointer onRegister(SvcMemory svcMemory, int svcNumber) {
                        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm, KeystoneMode.Arm)) {
                            KeystoneEncoded encoded = keystone.assemble(Arrays.asList(
                                    "nop",
                                    "bx lr"));
                            byte[] code = encoded.getMachineCode();
                            UnidbgPointer pointer = svcMemory.allocate(code.length, "objc_readClassPair");
                            pointer.write(0, code, 0, code.length);
                            return pointer;
                        }
                    }
                });
            }
            return old == WEAK_BIND ? _objc_readClassPair.peer : 0;
        }
        return 0;
    }
}
