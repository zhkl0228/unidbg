package com.github.unidbg.ios.struct.sysctl;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class DyldAllImageInfos32 extends UnidbgStructure {

    public DyldAllImageInfos32(Pointer p) {
        super(p);
    }

    public int version;
    public int infoArrayCount;
    public int infoArray;
    public int notification;
    public byte processDetachedFromSharedRegion;
    public byte libSystemInitialized;
    public int dyldImageLoadAddress;
    public int jitInfo;
    public int dyldVersion;
    public int errorMessage;
    public int terminationFlags;
    public int coreSymbolicationShmPage;
    public int systemOrderFlag;
    public int uuidArrayCount;
    public int uuidArray;
    public int dyldAllImageInfosAddress;
    public int initialImageCount;
    public int errorKind;
    public int errorClientOfDylibPath;
    public int errorTargetDylibPath;
    public int errorSymbol;
    public int sharedCacheSlide;
    public byte[] sharedCacheUUID = new byte[16];
    public int[] reserved = new int[16];

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("version", "infoArrayCount", "infoArray", "notification", "processDetachedFromSharedRegion", "libSystemInitialized",
                "dyldImageLoadAddress", "jitInfo", "dyldVersion", "errorMessage", "terminationFlags", "coreSymbolicationShmPage", "systemOrderFlag",
                "uuidArrayCount", "uuidArray", "dyldAllImageInfosAddress", "initialImageCount", "errorKind", "errorClientOfDylibPath", "errorTargetDylibPath", "errorSymbol",
                "sharedCacheSlide", "sharedCacheUUID", "reserved");
    }
}
