package com.github.unidbg.linux.struct;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class Dirent extends UnidbgStructure {

    public Dirent(Pointer p) {
        super(p);
    }

    public long d_ino;
    public long d_off;
    public short d_reclen;
    public byte d_type;
    public byte[] d_name = new byte[256];

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("d_ino", "d_off", "d_reclen", "d_type", "d_name");
    }

}
