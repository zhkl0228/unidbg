package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.dvm.api.Bitmap;
import com.sun.jna.Pointer;
import org.junit.Test;

import java.awt.image.BufferedImage;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import static org.junit.Assert.assertEquals;

public class BitmapTest {

    private static ByteBuffer encode(BufferedImage image) {
        ByteBuffer buffer = ByteBuffer.allocate(image.getWidth() * image.getHeight() * 4);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        for (int y = 0; y < image.getHeight(); y++) {
            for (int x = 0; x < image.getWidth(); x++) {
                int rgb = image.getRGB(x, y);
                // RGBA_8888 little-endian, 与 JniGraphics.lockPixels 保持一致
                buffer.putInt((((rgb >> 24) & 0xff) << 24) | ((rgb & 0xff) << 16) | (((rgb >> 8) & 0xff) << 8) | ((rgb >> 16) & 0xff));
            }
        }
        return buffer;
    }

    @Test
    public void unlockPixelsWritesBackNativeEdits() throws Exception {
        try (AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit().addBackendFactory(new Unicorn2Factory(true)).build()) {
            VM vm = emulator.createDalvikVM();

            BufferedImage image = new BufferedImage(2, 2, BufferedImage.TYPE_4BYTE_ABGR);
            image.setRGB(0, 0, 0xff112233);
            image.setRGB(1, 0, 0xff445566);
            image.setRGB(0, 1, 0xff778899);
            image.setRGB(1, 1, 0xffaabbcc);

            Bitmap bitmap = new Bitmap(vm, image);
            Pointer pointer = bitmap.lockPixels(emulator, image, encode(image));

            assertEquals(0x11, pointer.getByte(0) & 0xff); // R
            assertEquals(0x22, pointer.getByte(1) & 0xff); // G
            assertEquals(0x33, pointer.getByte(2) & 0xff); // B
            assertEquals(0xff, pointer.getByte(3) & 0xff); // A

            pointer.setInt(3 * 4, 0xff0000ff); // 原生侧把 (1,1) 改成不透明红色

            bitmap.unlockPixels();

            assertEquals(0xffff0000, image.getRGB(1, 1));
            assertEquals(0xff112233, image.getRGB(0, 0));
            assertEquals(0xff445566, image.getRGB(1, 0));
            assertEquals(0xff778899, image.getRGB(0, 1));
        }
    }

}
