package com.github.unidbg.virtualmodule.android;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.ArmSvc;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.virtualmodule.VirtualModule;
import com.sun.jna.Pointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Map;
import java.util.Random;

@SuppressWarnings("unused")
public class MediaNdkModule extends VirtualModule<VM> {

    private static final Logger log = LoggerFactory.getLogger(MediaNdkModule.class);

    public MediaNdkModule(Emulator<?> emulator, VM vm) {
        super(emulator, vm, "libmediandk.so");
    }

    @Override
    protected void onInitialize(Emulator<?> emulator, VM extra, Map<String, UnidbgPointer> symbols) {
        boolean is64Bit = emulator.is64Bit();
        SvcMemory svcMemory = emulator.getSvcMemory();
        symbols.put("AMediaDrm_createByUUID", svcMemory.registerSvc(is64Bit ? new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return createByUUID(emulator);
            }
        } : new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return createByUUID(emulator);
            }
        }));

        symbols.put("AMediaDrm_getPropertyByteArray", svcMemory.registerSvc(is64Bit ? new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return getPropertyByteArray(emulator);
            }
        } : new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return getPropertyByteArray(emulator);
            }
        }));

        symbols.put("AMediaDrm_getPropertyString", svcMemory.registerSvc(is64Bit ? new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return getPropertyString(emulator);
            }
        } : new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return getPropertyString(emulator);
            }
        }));

        symbols.put("AMediaDrm_release", svcMemory.registerSvc(is64Bit ? new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return release();
            }
        } : new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return release();
            }
        }));
    }


    public static final byte[] WIDE_VINE_UUID = {(byte) 0xed, (byte) 0xef, (byte) 0x8b, (byte) 0xa9,0x79, (byte) 0xd6,0x4a,
            (byte) 0xce, (byte) 0xa3, (byte) 0xc8,0x27, (byte) 0xdc, (byte) 0xd5,0x1d,0x21, (byte) 0xed};

    private long createByUUID(Emulator<?> emulator) {
        if (log.isDebugEnabled()) {
            log.debug("call createByUUID");
        }
        RegisterContext context = emulator.getContext();
        Pointer uuidPtr = context.getPointerArg(0);
        byte[] uuid = uuidPtr.getByteArray(0, 0x10);
        if(Arrays.equals(uuid, WIDE_VINE_UUID)){
            return emulator.getMemory().malloc(0x8, true).getPointer().peer;
        }
        throw new UnsupportedOperationException("createByUUID");
    }


    private long getPropertyByteArray(Emulator<?> emulator){
        RegisterContext context = emulator.getContext();
        Pointer propertyNamePtr = context.getPointerArg(1);
        Pointer propertyValuePtr = context.getPointerArg(2);
        String propertyName = propertyNamePtr.getString(0);
        if(propertyName.equals("deviceUniqueId")){
            MemoryBlock memoryBlock = emulator.getMemory().malloc(0x20, true);
            byte[] b = new byte[0x20];
            new Random().nextBytes(b);
            memoryBlock.getPointer().write(0, b, 0, 0x20);
            propertyValuePtr.setPointer(0, memoryBlock.getPointer());
            propertyValuePtr.setLong(emulator.getPointerSize(), 0x20);
            return 0;
        }
        throw new UnsupportedOperationException("getPropertyByteArray");
    }

    private MemoryBlock vendorPropertyBlock;

    private long getPropertyString(Emulator<?> emulator){
        RegisterContext context = emulator.getContext();
        Pointer propertyNamePtr = context.getPointerArg(1);
        Pointer propertyValuePtr = context.getPointerArg(2);
        String propertyName = propertyNamePtr.getString(0);
        if ("vendor".equals(propertyName)) {
            final String value = "Google";
            if (vendorPropertyBlock == null) {
                vendorPropertyBlock = emulator.getMemory().malloc(value.length(), true);
            }
            vendorPropertyBlock.getPointer().setString(0, value);

            propertyValuePtr.setPointer(0, vendorPropertyBlock.getPointer());
            if (emulator.is32Bit()) {
                propertyValuePtr.setInt(4, value.length());
            } else {
                propertyValuePtr.setLong(8, value.length());
            }
            return 0;
        }
        throw new UnsupportedOperationException("getPropertyString: " + propertyName);
    }

    private long release(){
        if (vendorPropertyBlock != null) {
            vendorPropertyBlock.free();
            vendorPropertyBlock = null;
        }
        return 0;
    }

}
