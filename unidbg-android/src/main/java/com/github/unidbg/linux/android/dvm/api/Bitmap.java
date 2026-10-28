package com.github.unidbg.linux.android.dvm.api;

import com.github.unidbg.Emulator;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.sun.jna.Pointer;

import java.awt.image.BufferedImage;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

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
        if (memoryBlock != null) {
            BufferedImage image = getValue();
            if (image != null) {
                int width = image.getWidth();
                int height = image.getHeight();
                ByteBuffer buffer = ByteBuffer.wrap(memoryBlock.getPointer().getByteArray(0, width * height * 4));
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                for (int y = 0; y < height; y++) {
                    for (int x = 0; x < width; x++) {
                        int argb = buffer.getInt(); // RGBA_8888 little-endian: A<<24 | B<<16 | G<<8 | R
                        int a = (argb >> 24) & 0xff;
                        int b = (argb >> 16) & 0xff;
                        int g = (argb >> 8) & 0xff;
                        int r = argb & 0xff;
                        image.setRGB(x, y, (a << 24) | (r << 16) | (g << 8) | b);
                    }
                }
            }
        }
        freeMemoryBlock(null);
    }

}
