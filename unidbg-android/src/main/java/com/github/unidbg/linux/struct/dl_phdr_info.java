package com.github.unidbg.linux.struct;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class dl_phdr_info extends UnidbgStructure {

    public dl_phdr_info(Pointer p) {
        super(p);
    }

    public Pointer dlpi_addr;
    public Pointer dlpi_name;
    public Pointer dlpi_phdr;
    public short dlpi_phnum;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("dlpi_addr", "dlpi_name", "dlpi_phdr", "dlpi_phnum");
    }

}
