package com.github.unidbg.ios.ipa;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.ArmSvc;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.hook.HookListener;
import com.github.unidbg.ios.struct.DispatchSourceType;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;

import java.util.Arrays;

class SymbolResolver implements HookListener {

    private final Emulator<DarwinFileIO> emulator;
    private UnidbgPointer _os_unfair_lock_lock, _os_unfair_lock_unlock;
    private UnidbgPointer _objc_readClassPair;
    private UnidbgPointer _objc_unsafeClaimAutoreleasedReturnValue;
    private UnidbgPointer __tlv_bootstrap;

    private UnidbgPointer __dispatch_source_type_memorypressure;
    private UnidbgPointer dispatch_source_type_memorypressure_init;

    public SymbolResolver(Emulator<DarwinFileIO> emulator) {
        this.emulator = emulator;
    }

    @Override
    public long hook(SvcMemory svcMemory, String libraryName, String symbolName, long old) {
        /*if (symbolName.contains("tlv_bootstrap")) {
            System.out.println("libraryName=" + libraryName + ", symbolName=" + symbolName + ", old=0x" + Long.toHexString(old));
        }*/
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
                        return self.peer + emulator.getPointerSize();
                    }
                } : new ArmSvc() {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        RegisterContext context = emulator.getContext();
                        UnidbgPointer self = context.getPointerArg(0);
                        return self.peer + emulator.getPointerSize();
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
