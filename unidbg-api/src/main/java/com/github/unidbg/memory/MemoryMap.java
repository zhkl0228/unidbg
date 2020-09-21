package com.github.unidbg.memory;

import com.github.unidbg.serialize.Serializable;

import java.io.DataOutput;
import java.io.IOException;

public class MemoryMap implements Serializable {

    public final long base;
    public final long size;
    public final int prot;

    public MemoryMap(long base, long size, int prot) {
        this.base = base;
        this.size = size;
        this.prot = prot;
    }

    @Override
    public void serialize(DataOutput out) throws IOException {
        out.writeLong(base);
        out.writeLong(size);
        out.writeInt(prot);
    }

    @Override
    public String toString() {
        return "MemoryMap{" +
                "base=0x" + Long.toHexString(base) +
                ", size=" + size +
                ", prot=" + prot +
                '}';
    }
}
