package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.util.Collections;
import java.util.List;

public class VprocMigLookupRequest extends UnicornStructure {

    public VprocMigLookupRequest(Pointer p) {
        super(p);
    }

    public NDR_record NDR;

    @Override
    protected List<String> getFieldOrder() {
        return Collections.singletonList("NDR");
    }

}
