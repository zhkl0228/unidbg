package com.github.unidbg.ios.ipa;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.ArmSvc;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.hook.HookListener;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnicornPointer;

class SymbolResolver implements HookListener {

    private final Emulator<DarwinFileIO> emulator;
    private UnicornPointer _os_unfair_lock_lock, _os_unfair_lock_unlock;

    public SymbolResolver(Emulator<DarwinFileIO> emulator) {
        this.emulator = emulator;
    }

    @Override
    public long hook(SvcMemory svcMemory, String libraryName, String symbolName, long old) {
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
        return 0;
    }
}
