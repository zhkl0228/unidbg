package cn.banny.unidbg.linux.android.dvm.api;

import cn.banny.unidbg.linux.android.dvm.DvmObject;
import cn.banny.unidbg.linux.android.dvm.VM;
import cn.banny.unidbg.memory.MemoryBlock;

import java.awt.image.BufferedImage;

public class Bitmap extends DvmObject<BufferedImage> {

    public Bitmap(VM vm, BufferedImage image) {
        super(vm.resolveClass("android/graphics/Bitmap"), image);
    }

    public MemoryBlock memoryBlock;

}
