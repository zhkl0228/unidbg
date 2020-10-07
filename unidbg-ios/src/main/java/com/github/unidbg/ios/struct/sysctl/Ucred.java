package com.github.unidbg.ios.struct.sysctl;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class Ucred extends UnidbgStructure {

    private static final int NGROUPS_MAX = 16; /* max supplemental group id's */

    public Ucred(Pointer p) {
        super(p);
    }

    public int cr_ref; /* reference count */
    public int cr_uid; /* effective user id */
    public short cr_ngroups; /* number of groups */
    public int[] cr_groups = new int[NGROUPS_MAX]; /* groups */

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("cr_ref", "cr_uid", "cr_ngroups", "cr_groups");
    }
}
