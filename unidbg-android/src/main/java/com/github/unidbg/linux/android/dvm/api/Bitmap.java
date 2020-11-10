package com.github.unidbg.linux.android.dvm.api;

import com.github.unidbg.Emulator;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.sun.jna.Pointer;

import java.awt.image.BufferedImage;
import java.nio.ByteBuffer;

public class Bitmap extends DvmObject<BufferedImage> {

    public Bitmap(VM vm, BufferedImage image) {
        super(vm.resolveClass("android/graphics/Bitmap"), image);
    }

    public Pointer lockPixels(Emulator<?> emulator, BufferedImage image, ByteBuffer buffer) {
        Pointer pointer = allocateMemoryBlock(emulator, image.getWidth() * image.getHeight() * 4);
        pointer.write(0, buffer.array(), 0, buffer.capacity());
        return pointer;
    }

    public void unlockPixels() {
        freeMemoryBlock(null);
    }

}
