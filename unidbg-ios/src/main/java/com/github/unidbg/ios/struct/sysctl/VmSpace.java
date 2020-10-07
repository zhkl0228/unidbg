package com.github.unidbg.ios.struct.sysctl;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class VmSpace extends UnidbgStructure {

    public VmSpace(Pointer p) {
        super(p);
    }

    public int vm_refcnt; /* number of references */
    public Pointer vm_shm; /* SYS5 shared memory private data XXX */
    public int vm_rssize; /* current resident set size in pages */
    public int vm_swrss; /* resident set size before last swap */
    public int vm_tsize; /* text size (pages) XXX */
    public int vm_dsize; /* data size (pages) XXX */
    public int vm_ssize; /* stack size (pages) */
    public Pointer vm_taddr; /* user virtual address of text XXX */
    public Pointer vm_daddr; /* user virtual address of data XXX */
    public Pointer vm_maxsaddr; /* user VA at max stack growth */

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("vm_refcnt", "vm_shm", "vm_rssize", "vm_swrss", "vm_tsize", "vm_dsize", "vm_ssize",
                "vm_taddr", "vm_daddr", "vm_maxsaddr");
    }

}
