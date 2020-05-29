package com.github.unidbg.ios.ipa;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.ArmSvc;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.hook.HookListener;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnicornPointer;

class SymbolResolver implements HookListener {

    private final Emulator<DarwinFileIO> emulator;
    private UnicornPointer _os_unfair_lock_lock, _os_unfair_lock_unlock;
    private UnicornPointer _objc_readClassPair;

    public SymbolResolver(Emulator<DarwinFileIO> emulator) {
        this.emulator = emulator;
    }

    @Override
    public long hook(SvcMemory svcMemory, String libraryName, String symbolName, long old) {
        /*if (symbolName.contains("AVAudioSession")) {
            System.out.println("libraryName=" + libraryName + ", symbolName=" + symbolName + ", old=0x" + Long.toHexString(old));
        }*/
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
                        RegisterContext context = emulator.getContext();
                        return context.getPointerArg(0).peer;
                    }
                } : new ArmSvc() {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        RegisterContext context = emulator.getContext();
                        return context.getPointerArg(0).peer;
                    }
                });
            }
//            return _objc_readClassPair.peer;
        }
        return 0;
    }
}
