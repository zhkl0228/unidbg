package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class VmRegionSubMapShortInfo64 extends UnidbgStructure {

    public VmRegionSubMapShortInfo64(Pointer p) {
        super(p);
    }

    public int protection; /* present access protection */
    public int max_protection; /* max avail through vm_prot */
    public int inheritance; /* behavior of map/obj on fork */

    public int offset; /* offset into object/map */
    public int userTag; /* user tag on map entry */
    public int refCount; /* obj/map mappers, etc */

    public short shadowDepth; /* only for obj */
    public byte externalPager; /* only for obj */
    public byte shareMode; /* see enumeration */

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("protection", "max_protection", "inheritance", "offset", "userTag", "refCount", "shadowDepth", "externalPager", "shareMode");
    }

}
