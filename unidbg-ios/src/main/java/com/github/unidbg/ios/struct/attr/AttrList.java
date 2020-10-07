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
    public int commonattr; /* common attribute group */
    public int volattr; /* Volume attribute group */
    public int dirattr; /* directory attribute group */
    public int fileattr; /* file attribute group */
    public int forkattr; /* fork attribute group */

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("bitmapcount", "reserved", "commonattr", "volattr", "dirattr", "fileattr", "forkattr");
    }

}
