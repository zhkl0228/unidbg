package com.github.unidbg.virtualmodule.android;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.ArmSvc;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.virtualmodule.VirtualModule;
import com.sun.jna.Pointer;
import java.util.Arrays;
import java.util.Map;
import java.util.Random;

public class MediandkModule extends VirtualModule {

    public MediandkModule(Emulator<?> emulator, VM vm) {
        super(emulator, vm, "libmediandk.so");
    }


    @Override
    protected void onInitialize(Emulator emulator, Object extra, Map symbols) {
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
                return getPropertyByteArray64(emulator);
            }
        } : new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return getPropertyByteArray32(emulator);
            }
        }));

        symbols.put("AMediaDrm_release", svcMemory.registerSvc(is64Bit ? new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return release(emulator);
            }
        } : new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return release(emulator);
            }
        }));
    }


    public static final byte[] wideVineUuid = {(byte) 0xed, (byte) 0xef, (byte) 0x8b, (byte) 0xa9,0x79, (byte) 0xd6,0x4a,
            (byte) 0xce, (byte) 0xa3, (byte) 0xc8,0x27, (byte) 0xdc, (byte) 0xd5,0x1d,0x21, (byte) 0xed};
    private static long createByUUID(Emulator<?> emulator) {
        System.out.println("call createByUUID");
        RegisterContext context = emulator.getContext();
        Pointer uuidPtr = context.getPointerArg(0);
        byte[] uuid = uuidPtr.getByteArray(0, 0x10);
        if(Arrays.equals(uuid, wideVineUuid)){
            return emulator.getMemory().malloc(0x8, true).getPointer().peer;
        }
        return 0;
    }


    private static long getPropertyByteArray64(Emulator<?> emulator){
        RegisterContext context = emulator.getContext();
        Pointer aMediaDrmPtr = context.getPointerArg(0);
        Pointer propertyNamePtr = context.getPointerArg(1);
        Pointer propertyValuePtr = context.getPointerArg(2);
        String propertyName = propertyNamePtr.getString(0);
        if(propertyName.equals("deviceUniqueId")){
            MemoryBlock memoryBlock = emulator.getMemory().malloc(0x20, true);
            byte[] b = new byte[0x20];
            new Random().nextBytes(b);
            memoryBlock.getPointer().write(0, b, 0, 0x20);
            propertyValuePtr.setLong(0, memoryBlock.getPointer().peer);
            propertyValuePtr.setLong(8, 0x20);
        }

        return 0;
    };

    private static long getPropertyByteArray32(Emulator<?> emulator){
        RegisterContext context = emulator.getContext();
        Pointer aMediaDrmPtr = context.getPointerArg(0);
        Pointer propertyNamePtr = context.getPointerArg(1);
        Pointer propertyValuePtr = context.getPointerArg(2);
        String propertyName = propertyNamePtr.getString(0);
        if(propertyName.equals("deviceUniqueId")){
            MemoryBlock memoryBlock = emulator.getMemory().malloc(0x20, true);
            byte[] b = new byte[0x20];
            new Random().nextBytes(b);
            memoryBlock.getPointer().write(0, b, 0, 0x20);
            propertyValuePtr.setInt(0, (int) memoryBlock.getPointer().peer);
            propertyValuePtr.setInt(4, 0x20);
        }
        return 0;
    };

    private static long release(Emulator<?> emulator){
        return 0;
    };


}
