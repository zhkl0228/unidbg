package com.github.unidbg.ios.ipa;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.ArmSvc;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.hook.HookListener;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnicornPointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;

import java.util.Arrays;

class SymbolResolver implements HookListener {

    private final Emulator<DarwinFileIO> emulator;
    private UnicornPointer _os_unfair_lock_lock, _os_unfair_lock_unlock;
    private UnicornPointer _objc_readClassPair;
    private UnicornPointer _objc_unsafeClaimAutoreleasedReturnValue;

    public SymbolResolver(Emulator<DarwinFileIO> emulator) {
        this.emulator = emulator;
    }

    @Override
    public long hook(SvcMemory svcMemory, String libraryName, String symbolName, long old) {
        /*if (symbolName.contains("AVAudioSession")) {
            System.out.println("libraryName=" + libraryName + ", symbolName=" + symbolName + ", old=0x" + Long.toHexString(old));
        }*/
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
        if ("_objc_readClassPair".equals(symbolName)) {
            if (_objc_readClassPair == null) {
                _objc_readClassPair = svcMemory.registerSvc(emulator.is64Bit() ? new Arm64Svc() {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        throw new UnsupportedOperationException();
                    }
                    @Override
                    public UnicornPointer onRegister(SvcMemory svcMemory, int svcNumber) {
                        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian)) {
                            KeystoneEncoded encoded = keystone.assemble(Arrays.asList(
                                    "nop",
                                    "ret"));
                            byte[] code = encoded.getMachineCode();
                            UnicornPointer pointer = svcMemory.allocate(code.length, "objc_readClassPair");
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
                    public UnicornPointer onRegister(SvcMemory svcMemory, int svcNumber) {
                        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm, KeystoneMode.Arm)) {
                            KeystoneEncoded encoded = keystone.assemble(Arrays.asList(
                                    "nop",
                                    "bx lr"));
                            byte[] code = encoded.getMachineCode();
                            UnicornPointer pointer = svcMemory.allocate(code.length, "objc_readClassPair");
                            pointer.write(0, code, 0, code.length);
                            return pointer;
                        }
                    }
                });
            }
            return old == -2 ? _objc_readClassPair.peer : 0; // weak bind
        }
        return 0;
    }
}
