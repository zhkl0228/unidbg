package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

public class IOServiceGetMatchingServiceRequest extends UnidbgStructure {

    public IOServiceGetMatchingServiceRequest(Pointer p) {
        super(p);
    }

    public NDR_record NDR;
    public int pad;
    public int size;

    public String getMatching() {
        Pointer pointer = getPointer().share(size());
        return new String(pointer.getByteArray(0, size), StandardCharsets.UTF_8).trim();
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "pad", "size");
    }

}
