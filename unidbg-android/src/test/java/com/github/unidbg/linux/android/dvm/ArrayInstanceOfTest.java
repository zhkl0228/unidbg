package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.linux.android.dvm.array.IntArray;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ArrayInstanceOfTest {

    private static boolean isInstanceOf(VM vm, DvmObject<?> object, String className) {
        return object.isInstanceOf(vm.resolveClass(className));
    }

    @Test
    public void objectArrayIsInstanceOf() throws Exception {
        try (AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit().addBackendFactory(new Unicorn2Factory(true)).build()) {
            VM vm = emulator.createDalvikVM();
            ArrayObject strings = ArrayObject.newObjectArray(vm.resolveClass("java/lang/String"), new DvmObject<?>[2]);
            assertTrue(isInstanceOf(vm, strings, "[Ljava/lang/String;"));
            assertTrue(isInstanceOf(vm, strings, "[Ljava/lang/Object;"));
            assertTrue(isInstanceOf(vm, strings, "java/io/Serializable"));
            assertFalse(isInstanceOf(vm, strings, "[Ljava/lang/Integer;"));
            assertFalse(isInstanceOf(vm, new IntArray(vm, new int[1]), "[Ljava/lang/Object;"));

            ArrayObject legacy = new ArrayObject(new StringObject(vm, "a"));
            assertTrue(isInstanceOf(vm, legacy, "[Ljava/lang/Object;"));
            assertFalse(isInstanceOf(vm, legacy, "[Ljava/lang/Integer;"));
        }
    }
}
