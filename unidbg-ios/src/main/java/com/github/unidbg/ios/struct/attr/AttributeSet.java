package com.github.unidbg.ios.struct.attr;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class AttributeSet extends UnidbgStructure {

    public AttributeSet(Pointer p) {
        super(p);
    }

    public int commonattr; /* common attribute group */
    public int volattr; /* Volume attribute group */
    public int dirattr; /* directory attribute group */
    public int fileattr; /* file attribute group */
    public int forkattr; /* fork attribute group */

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("commonattr", "volattr", "dirattr", "fileattr", "forkattr");
    }

}
