package com.github.unidbg.linux.struct;

import com.github.unidbg.file.linux.StatStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class Stat64 extends StatStructure {

    public Stat64(Pointer p) {
        super(p);
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("st_dev", "st_ino");
    }

}
