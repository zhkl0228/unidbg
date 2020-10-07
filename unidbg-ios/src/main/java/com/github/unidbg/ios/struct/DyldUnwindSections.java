package com.github.unidbg.ios.struct;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class DyldUnwindSections extends UnidbgStructure {

    public DyldUnwindSections(Pointer p) {
        super(p);
    }

    public long mach_header;
    public long dwarf_section;
    public long dwarf_section_length;
    public long compact_unwind_section;
    public long compact_unwind_section_length;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("mach_header", "dwarf_section", "dwarf_section_length", "compact_unwind_section", "compact_unwind_section_length");
    }

}
