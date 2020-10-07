package com.github.unidbg.ios.struct.sysctl;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class DyldAllImageInfos64 extends UnidbgStructure {

    public DyldAllImageInfos64(Pointer p) {
        super(p);
    }

    public int version;
    public int infoArrayCount;
    public Pointer infoArray;
    public Pointer notification;
    public byte processDetachedFromSharedRegion;
    public byte libSystemInitialized;
    public Pointer dyldImageLoadAddress;
    public Pointer jitInfo;
    public Pointer dyldVersion;
    public Pointer errorMessage;
    public long terminationFlags;
    public Pointer coreSymbolicationShmPage;
    public long systemOrderFlag;
    public long uuidArrayCount;
    public Pointer uuidArray;
    public Pointer dyldAllImageInfosAddress;
    public long initialImageCount;
    public long errorKind;
    public Pointer errorClientOfDylibPath;
    public Pointer errorTargetDylibPath;
    public Pointer errorSymbol;
    public long sharedCacheSlide;
    public byte[] sharedCacheUUID = new byte[16];
    public long[] reserved = new long[16];

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("version", "infoArrayCount", "infoArray", "notification", "processDetachedFromSharedRegion", "libSystemInitialized",
                "dyldImageLoadAddress", "jitInfo", "dyldVersion", "errorMessage", "terminationFlags", "coreSymbolicationShmPage", "systemOrderFlag",
                "uuidArrayCount", "uuidArray", "dyldAllImageInfosAddress", "initialImageCount", "errorKind", "errorClientOfDylibPath", "errorTargetDylibPath", "errorSymbol",
                "sharedCacheSlide", "sharedCacheUUID", "reserved");
    }
}
