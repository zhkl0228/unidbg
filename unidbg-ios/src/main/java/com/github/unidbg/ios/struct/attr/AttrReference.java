package com.github.unidbg.ios.struct.attr;

import com.github.unidbg.arm.ARM;
import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class AttrReference extends UnidbgStructure {

    private final byte[] bytes;

    public AttrReference(Pointer p, byte[] bytes) {
        super(p);
        this.bytes = bytes;
        attr_length = (int) ARM.alignSize(bytes.length + 1, 8);
    }

    public int attr_dataoffset;
    public int attr_length;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("attr_dataoffset", "attr_length");
    }

    private boolean started;

    public void check(UnidbgStructure structure, int size) {
        if (structure == this) {
            started = true;
        }

        if (started) {
            attr_dataoffset += size;
        }
    }

    public void writeAttr(Pointer pointer) {
        pointer.write(0, Arrays.copyOf(bytes, attr_length), 0, attr_length);
        pack();
    }
}
