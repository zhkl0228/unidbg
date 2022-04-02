package com.github.unidbg.ios.struct.attr;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class AttrList extends UnidbgStructure {

    public AttrList(Pointer p) {
        super(p);
        unpack();
    }

    public short bitmapcount; /* number of attr. bit sets in list (should be 5) */
    public short reserved; /* (to maintain 4-byte alignment) */

    public AttributeSet attributeSet;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("bitmapcount", "reserved", "attributeSet");
    }

}
