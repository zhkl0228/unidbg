package com.github.unidbg.linux.android.dvm.api;

import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.MemoryBlockObject;
import com.github.unidbg.linux.android.dvm.VM;

import java.awt.image.BufferedImage;

public class Bitmap extends DvmObject<BufferedImage> implements MemoryBlockObject {

    public Bitmap(VM vm, BufferedImage image) {
        super(vm.resolveClass("android/graphics/Bitmap"), image);
    }

}
