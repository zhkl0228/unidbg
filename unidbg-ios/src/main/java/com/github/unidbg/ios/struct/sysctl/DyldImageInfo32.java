package com.github.unidbg.ios.struct.sysctl;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class DyldImageInfo32 extends UnidbgStructure {

    public DyldImageInfo32(Pointer p) {
        super(p);
    }

    public Pointer imageLoadAddress; /* base address image is mapped into */
    public Pointer imageFilePath; /* path dyld used to load the image */
    public int imageFileModDate; /* time_t of image file */

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("imageLoadAddress", "imageFilePath", "imageFileModDate");
    }
}
