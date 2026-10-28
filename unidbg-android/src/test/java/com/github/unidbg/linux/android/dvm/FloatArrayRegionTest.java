package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.dvm.array.FloatArray;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.pointer.UnidbgPointer;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class FloatArrayRegionTest {

    private static final int GET_FLOAT_ARRAY_REGION_INDEX = 205;

    @Test
    public void getFloatArrayRegionArm64() throws Exception {
        try (AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit()
                .addBackendFactory(new Unicorn2Factory(true)).build()) {
            copyRegion(emulator);
        }
    }

    @Test
    public void getFloatArrayRegionArm32() throws Exception {
        try (AndroidEmulator emulator = AndroidEmulatorBuilder.for32Bit()
                .addBackendFactory(new Unicorn2Factory(true)).build()) {
            copyRegion(emulator);
        }
    }

    private void copyRegion(AndroidEmulator emulator) {
        BaseVM vm = (BaseVM) emulator.createDalvikVM();
        FloatArray array = new FloatArray(vm, new float[]{1.5f, -2.25f, 3f});
        int handle = vm.addLocalObject(array);

        int start = 1;
        int length = 2;
        MemoryBlock block = emulator.getMemory().malloc(length * 4, true);

        long env = UnidbgPointer.nativeValue(vm.getJNIEnv());
        UnidbgPointer functionTable = UnidbgPointer.pointer(emulator, env).getPointer(0);
        assert functionTable != null;
        long function = functionTable.getPointer(GET_FLOAT_ARRAY_REGION_INDEX * emulator.getPointerSize()).peer;
        long buffer = block.getPointer().peer;

        Number envArg = pointerArg(emulator, env);
        Number bufferArg = pointerArg(emulator, buffer);
        Number result = emulator.eFunc(function, envArg, handle, start, length, bufferArg);
        assertEquals(0, result.intValue());
        assertArrayEquals(new float[]{-2.25f, 3f}, block.getPointer().getFloatArray(0, length), 0f);
        block.free();
    }

    private static Number pointerArg(AndroidEmulator emulator, long value) {
        if (emulator.is64Bit()) {
            return value;
        }
        return (int) value;
    }
}
