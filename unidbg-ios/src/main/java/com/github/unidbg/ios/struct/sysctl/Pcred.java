package com.github.unidbg.ios.struct.sysctl;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class Pcred extends UnidbgStructure {

    public Pcred(Pointer p) {
        super(p);
    }

    public byte[] pc_lock = new byte[72]; /* opaque content */
    public Pointer pc_ucred; /* Current credentials. */
    public int p_ruid; /* Real user id. */
    public int p_svuid; /* Saved effective user id. */
    public int p_rgid; /* Real group id. */
    public int p_svgid; /* Saved effective group id. */
    public int p_refcnt; /* Number of references. */

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("pc_lock", "pc_ucred", "p_ruid", "p_svuid", "p_rgid", "p_svgid", "p_refcnt");
    }

}
