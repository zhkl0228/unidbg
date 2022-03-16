package com.github.unidbg.linux.struct;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class dl_phdr_info64 extends UnidbgStructure {

    public dl_phdr_info64(Pointer p) {
        super(p);
    }

    public long dlpi_addr; // ptr
    public long dlpi_name; // ptr
    public long dlpi_phdr; // ptr
    public short dlpi_phnum;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("dlpi_addr", "dlpi_name", "dlpi_phdr", "dlpi_phnum");
    }

}
