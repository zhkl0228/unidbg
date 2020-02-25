package com.github.unidbg.virtualmodule.android;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.ArmSvc;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.virtualmodule.VirtualModule;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.UnicornException;

import java.util.Map;

public class AndroidModule extends VirtualModule {

    private static final Log log = LogFactory.getLog(AndroidModule.class);

    public AndroidModule(Emulator<?> emulator, VM vm) {
        super(emulator, vm, "libandroid.so");
    }

    @Override
    protected void onInitialize(Emulator<?> emulator, final VM vm, Map<String, UnicornPointer> symbols) {
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
                throw new UnicornException();
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
        UnicornPointer assetManager = context.getPointerArg(1);
        DvmObject<?> obj = vm.getObject(assetManager.toUIntPeer());
        if (log.isDebugEnabled()) {
            log.debug("AAssetManager_fromJava env=" + env + ", assetManager=" + obj.getObjectType());
        }
        return assetManager.peer;
    }

    private static long open(Emulator<?> emulator, VM vm) {
        RegisterContext context = emulator.getContext();
        Pointer amgr = context.getPointerArg(0);
        String filename = context.getPointerArg(1).getString(0);
        int mode = context.getIntArg(2);
        if (log.isDebugEnabled()) {
            log.debug("AAssetManager_open amgr=" + amgr + ", filename=" + filename + ", mode=" + mode);
        }
        final int AASSET_MODE_STREAMING = 2;
        final int AASSET_MODE_BUFFER = 3;
        if (mode == AASSET_MODE_STREAMING || AASSET_MODE_BUFFER == mode) {
            byte[] data = vm.openAsset(filename);
            if (data != null) {
                Memory memory = emulator.getMemory();
                MemoryBlock block = memory.malloc(data.length + 8, true);
                block.getPointer().setInt(0, 0); // index
                block.getPointer().setInt(4, data.length);
                block.getPointer().write(8, data, 0, data.length);
                return vm.addLocalObject(vm.resolveClass("android/content/res/Asset").newObject(block));
            }
        }
        throw new UnicornException("filename=" + filename + ", mode=" + mode);
    }

    private static long close(Emulator<?> emulator, VM vm) {
        RegisterContext context = emulator.getContext();
        UnicornPointer asset = context.getPointerArg(0);
        DvmObject<?> obj = vm.getObject(asset.toUIntPeer());
        MemoryBlock block = (MemoryBlock) obj.getValue();
        if (log.isDebugEnabled()) {
            log.debug("AAsset_close asset=" + asset + ", pointer=" + block.getPointer());
        }
        block.free(true);
        return 0;
    }

    private static long getBuffer(Emulator<?> emulator, VM vm) {
        RegisterContext context = emulator.getContext();
        UnicornPointer asset = context.getPointerArg(0);
        DvmObject<?> obj = vm.getObject(asset.toUIntPeer());
        MemoryBlock block = (MemoryBlock) obj.getValue();
        UnicornPointer buffer = block.getPointer().share(8, 0);
        if (log.isDebugEnabled()) {
            log.debug("AAsset_getBuffer asset=" + asset + ", buffer=" + buffer);
        }
        return buffer.peer;
    }

    private static long getLength(Emulator<?> emulator, VM vm) {
        RegisterContext context = emulator.getContext();
        UnicornPointer asset = context.getPointerArg(0);
        DvmObject<?> obj = vm.getObject(asset.toUIntPeer());
        MemoryBlock block = (MemoryBlock) obj.getValue();
        int length = block.getPointer().getInt(4);
        if (log.isDebugEnabled()) {
            log.debug("AAsset_getLength asset=" + asset + ", length=" + length);
        }
        return length;
    }

    private static long read(Emulator<?> emulator, VM vm) {
        RegisterContext context = emulator.getContext();
        UnicornPointer asset = context.getPointerArg(0);
        Pointer buf = context.getPointerArg(1);
        int count = context.getIntArg(2);
        DvmObject<?> obj = vm.getObject(asset.toUIntPeer());
        MemoryBlock block = (MemoryBlock) obj.getValue();
        Pointer pointer = block.getPointer();
        int index = pointer.getInt(0);
        int length = pointer.getInt(4);
        Pointer data = pointer.share(8, 0);
        if (log.isDebugEnabled()) {
            log.debug("AAsset_read asset=" + asset + ", buf=" + buf + ", count=" + count);
        }
        int remaining = length - index;
        int read = Math.min(remaining, count);
        pointer.setInt(0, index + read);
        byte[] bytes = data.getByteArray(index, read);
        buf.write(0, bytes, 0, bytes.length);
        return bytes.length;
    }

}
