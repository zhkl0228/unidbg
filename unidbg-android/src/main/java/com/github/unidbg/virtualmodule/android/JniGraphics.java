package com.github.unidbg.virtualmodule.android;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.ArmSvc;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.api.Bitmap;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.utils.Inspector;
import com.github.unidbg.virtualmodule.VirtualModule;
import com.sun.jna.Pointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.awt.image.BufferedImage;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Map;

public class JniGraphics extends VirtualModule<VM> {

    private static final Logger log = LoggerFactory.getLogger(JniGraphics.class);

    public JniGraphics(Emulator<?> emulator, VM vm) {
        super(emulator, vm, "libjnigraphics.so");
    }

    @Override
    protected void onInitialize(Emulator<?> emulator, final VM vm, Map<String, UnidbgPointer> symbols) {
        boolean is64Bit = emulator.is64Bit();
        SvcMemory svcMemory = emulator.getSvcMemory();
        symbols.put("AndroidBitmap_getInfo", svcMemory.registerSvc(is64Bit ? new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return getInfo(emulator, vm);
            }
        } : new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return getInfo(emulator, vm);
            }
        }));
        symbols.put("AndroidBitmap_lockPixels", svcMemory.registerSvc(is64Bit ? new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return lockPixels(emulator, vm);
            }
        } : new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return lockPixels(emulator, vm);
            }
        }));
        symbols.put("AndroidBitmap_unlockPixels", svcMemory.registerSvc(is64Bit ? new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return unlockPixels(emulator, vm);
            }
        } : new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return unlockPixels(emulator, vm);
            }
        }));
    }

    private static final int ANDROID_BITMAP_FORMAT_RGBA_8888 = 1;
    private static final int ANDROID_BITMAP_RESULT_SUCCESS = 0;

    private static long getInfo(Emulator<?> emulator, VM vm) {
        RegisterContext context = emulator.getContext();
        Pointer env = context.getPointerArg(0);
        UnidbgPointer jbitmap = context.getPointerArg(1);
        Pointer info = context.getPointerArg(2);
        Bitmap bitmap = vm.getObject(jbitmap.toIntPeer());
        BufferedImage image = bitmap.getValue();
        if (log.isDebugEnabled()) {
            log.debug("AndroidBitmap_getInfo env={}, width={}, height={}, stride={}, info={}", env, image.getWidth(), image.getHeight(), image.getWidth() * 4, info);
        }
        info.setInt(0, image.getWidth());
        info.setInt(4, image.getHeight());
        info.setInt(8, image.getWidth() * 4); // stride
        info.setInt(12, ANDROID_BITMAP_FORMAT_RGBA_8888);
        info.setInt(16, 0); // flags
        return ANDROID_BITMAP_RESULT_SUCCESS;
    }

    private static long lockPixels(Emulator<?> emulator, VM vm) {
        RegisterContext context = emulator.getContext();
        Pointer env = context.getPointerArg(0);
        UnidbgPointer jbitmap = context.getPointerArg(1);
        Pointer addrPtr = context.getPointerArg(2);
        Bitmap bitmap = vm.getObject(jbitmap.toIntPeer());
        BufferedImage image = bitmap.getValue();
        if (image.getType() != BufferedImage.TYPE_4BYTE_ABGR) {
            throw new IllegalStateException("image type=" + image.getType());
        }

        if (addrPtr != null) {
            ByteBuffer buffer = ByteBuffer.allocate(image.getWidth() * image.getHeight() * 4);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            for (int y = 0; y < image.getHeight(); y++) {
                for (int x = 0; x < image.getWidth(); x++) {
                    int rgb = image.getRGB(x, y);
                    buffer.putInt((((rgb >> 24) & 0xff) << 24) | ((rgb & 0xff) << 16) | (((rgb >> 8) & 0xff) <<  8) | ((rgb >> 16) & 0xff)); // convert TYPE_4BYTE_ABGR to ARGB_8888
                }
            }

            Pointer pointer = bitmap.lockPixels(emulator, image, buffer);
            addrPtr.setPointer(0, pointer);

            if (log.isDebugEnabled()) {
                log.debug(Inspector.inspectString(buffer.array(), "AndroidBitmap_lockPixels buffer=" + buffer));
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("AndroidBitmap_lockPixels env={}, bitmap={}, addrPtr={}", env, bitmap, addrPtr);
        }
        return ANDROID_BITMAP_RESULT_SUCCESS;
    }

    private static long unlockPixels(Emulator<?> emulator, VM vm) {
        RegisterContext context = emulator.getContext();
        Pointer env = context.getPointerArg(0);
        UnidbgPointer jbitmap = context.getPointerArg(1);
        Bitmap bitmap = vm.getObject(jbitmap.toIntPeer());
        bitmap.unlockPixels();
        if (log.isDebugEnabled()) {
            log.debug("AndroidBitmap_unlockPixels env={}, bitmap={}", env, bitmap);
        }
        return ANDROID_BITMAP_RESULT_SUCCESS;
    }

}
