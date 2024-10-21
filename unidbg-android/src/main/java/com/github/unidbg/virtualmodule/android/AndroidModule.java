package com.github.unidbg.virtualmodule.android;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.ArmSvc;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.api.Asset;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.virtualmodule.VirtualModule;
import com.sun.jna.Pointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

public class AndroidModule extends VirtualModule<VM> {

    private static final Logger log = LoggerFactory.getLogger(AndroidModule.class);

    public AndroidModule(Emulator<?> emulator, VM vm) {
        super(emulator, vm, "libandroid.so");
    }

    @Override
    protected void onInitialize(Emulator<?> emulator, final VM vm, Map<String, UnidbgPointer> symbols) {
        boolean is64Bit = emulator.is64Bit();
        SvcMemory svcMemory = emulator.getSvcMemory();
        symbols.put("AAssetManager_fromJava", svcMemory.registerSvc(is64Bit ? new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return fromJava(emulator, vm);
            }
        } : new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return fromJava(emulator, vm);
            }
        }));
        symbols.put("AAssetManager_open", svcMemory.registerSvc(is64Bit ? new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return open(emulator, vm);
            }
        } : new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return open(emulator, vm);
            }
        }));
        symbols.put("AAsset_close", svcMemory.registerSvc(is64Bit ? new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return close(emulator, vm);
            }
        } : new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return close(emulator, vm);
            }
        }));
        symbols.put("AAsset_getBuffer", svcMemory.registerSvc(is64Bit ? new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return getBuffer(emulator, vm);
            }
        } : new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return getBuffer(emulator, vm);
            }
        }));
        symbols.put("AAsset_getLength", svcMemory.registerSvc(is64Bit ? new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return getLength(emulator, vm);
            }
        } : new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return getLength(emulator, vm);
            }
        }));
        symbols.put("AAsset_read", svcMemory.registerSvc(is64Bit ? new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return read(emulator, vm);
            }
        } : new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return read(emulator, vm);
            }
        }));
    }

    private static long fromJava(Emulator<?> emulator, VM vm) {
        RegisterContext context = emulator.getContext();
        Pointer env = context.getPointerArg(0);
        UnidbgPointer assetManager = context.getPointerArg(1);
        DvmObject<?> obj = vm.getObject(assetManager.toIntPeer());
        if (log.isDebugEnabled()) {
            log.debug("AAssetManager_fromJava env={}, assetManager={}, LR={}", env, obj.getObjectType(), context.getLRPointer());
        }
        return assetManager.peer;
    }

    private static long open(Emulator<?> emulator, VM vm) {
        RegisterContext context = emulator.getContext();
        Pointer amgr = context.getPointerArg(0);
        String filename = context.getPointerArg(1).getString(0);
        int mode = context.getIntArg(2);
        if (log.isDebugEnabled()) {
            log.debug("AAssetManager_open amgr={}, filename={}, mode={}, LR={}", amgr, filename, mode, context.getLRPointer());
        }
        final int AASSET_MODE_UNKNOWN = 0;
        final int AASSET_MODE_RANDOM = 1;
        final int AASSET_MODE_STREAMING = 2;
        final int AASSET_MODE_BUFFER = 3;
        if (mode == AASSET_MODE_STREAMING || AASSET_MODE_BUFFER == mode ||
                mode == AASSET_MODE_UNKNOWN || mode == AASSET_MODE_RANDOM) {
            byte[] data = vm.openAsset(filename);
            if (data == null) {
                return 0L;
            }
            Asset asset = new Asset(vm, filename);
            asset.open(emulator, data);
            return vm.addLocalObject(asset);
        }
        throw new BackendException("filename=" + filename + ", mode=" + mode + ", LR=" + context.getLRPointer());
    }

    private static long close(Emulator<?> emulator, VM vm) {
        RegisterContext context = emulator.getContext();
        UnidbgPointer pointer = context.getPointerArg(0);
        Asset asset = vm.getObject(pointer.toIntPeer());
        asset.close();
        if (log.isDebugEnabled()) {
            log.debug("AAsset_close pointer={}, LR={}", pointer, context.getLRPointer());
        }
        return 0;
    }

    private static long getBuffer(Emulator<?> emulator, VM vm) {
        RegisterContext context = emulator.getContext();
        UnidbgPointer pointer = context.getPointerArg(0);
        Asset asset = vm.getObject(pointer.toIntPeer());
        UnidbgPointer buffer = asset.getBuffer();
        if (log.isDebugEnabled()) {
            log.debug("AAsset_getBuffer pointer={}, buffer={}, LR={}", pointer, buffer, context.getLRPointer());
        }
        return buffer.peer;
    }

    private static long getLength(Emulator<?> emulator, VM vm) {
        RegisterContext context = emulator.getContext();
        UnidbgPointer pointer = context.getPointerArg(0);
        Asset asset = vm.getObject(pointer.toIntPeer());
        int length = asset.getLength();
        if (log.isDebugEnabled()) {
            log.debug("AAsset_getLength pointer={}, length={}, LR={}", pointer, length, context.getLRPointer());
        }
        return length;
    }

    private static long read(Emulator<?> emulator, VM vm) {
        RegisterContext context = emulator.getContext();
        UnidbgPointer pointer = context.getPointerArg(0);
        Pointer buf = context.getPointerArg(1);
        int count = context.getIntArg(2);
        Asset asset = vm.getObject(pointer.toIntPeer());
        byte[] bytes = asset.read(count);
        if (log.isDebugEnabled()) {
            log.debug("AAsset_read pointer={}, buf={}, count={}, LR={}", pointer, buf, count, context.getLRPointer());
        }
        buf.write(0, bytes, 0, bytes.length);
        return bytes.length;
    }

}
