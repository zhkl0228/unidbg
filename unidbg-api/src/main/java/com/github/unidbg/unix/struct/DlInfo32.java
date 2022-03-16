package com.github.unidbg.unix.struct;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class DlInfo32 extends UnidbgStructure {

    public DlInfo32(Pointer p) {
        super(p);
    }

    public int dli_fname; /* Pathname of shared object */
    public int dli_fbase; /* Base address of shared object */
    public int dli_sname; /* Name of nearest symbol */
    public int dli_saddr; /* Address of nearest symbol */

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("dli_fname", "dli_fbase", "dli_sname", "dli_saddr");
    }

}
