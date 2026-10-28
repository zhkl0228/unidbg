package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.dvm.array.CharArray;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.pointer.UnidbgPointer;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class CharArrayTest {

    private static final int NEW_CHAR_ARRAY = 177;
    private static final int GET_CHAR_ARRAY_ELEMENTS = 185;
    private static final int RELEASE_CHAR_ARRAY_ELEMENTS = 193;
    private static final int GET_CHAR_ARRAY_REGION = 201;
    private static final int SET_CHAR_ARRAY_REGION = 209;

    @Test
    public void charArrayArm64() throws Exception {
        try (AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit().addBackendFactory(new Unicorn2Factory(true)).build()) {
            check(emulator);
        }
    }

    @Test
    public void charArrayArm32() throws Exception {
        try (AndroidEmulator emulator = AndroidEmulatorBuilder.for32Bit().addBackendFactory(new Unicorn2Factory(true)).build()) {
            check(emulator);
        }
    }

    private void check(AndroidEmulator emulator) {
        BaseVM vm = (BaseVM) emulator.createDalvikVM();
        CharArray array = new CharArray(vm, "sign".toCharArray());
        assertEquals(4, array.length());
        assertTrue(array.isInstanceOf(vm.resolveClass("[C")));

        UnidbgPointer pointer = array._GetArrayCritical(emulator, null);
        assertEquals('s', (char) pointer.getShort(0));
        assertEquals('n', (char) pointer.getShort(6));
        pointer.setShort(0, (short) 'S');
        array._ReleaseArrayCritical(pointer, 0);
        assertEquals('S', array.getValue()[0]);

        jniRoundTrip(emulator, vm);
    }

    private void jniRoundTrip(AndroidEmulator emulator, BaseVM vm) {
        long env = UnidbgPointer.nativeValue(vm.getJNIEnv());
        UnidbgPointer functionTable = UnidbgPointer.pointer(emulator, env).getPointer(0);
        assertNotNull(functionTable);

        Number handleResult = emulator.eFunc(function(functionTable, emulator, NEW_CHAR_ARRAY), pointerArg(emulator, env), 4);
        int handle = handleResult.intValue();
        CharArray array = vm.getObject(handle);
        assertEquals(4, array.length());

        MemoryBlock source = emulator.getMemory().malloc(4 * 2, true);
        UnidbgPointer sourcePointer = source.getPointer();
        for (int i = 0; i < 4; i++) {
            sourcePointer.setShort((long) i * 2, (short) "sign".charAt(i));
        }
        Number setResult = emulator.eFunc(function(functionTable, emulator, SET_CHAR_ARRAY_REGION), pointerArg(emulator, env), handle, 0, 4, pointerArg(emulator, sourcePointer.peer));
        assertEquals(0, setResult.intValue());
        source.free();
        assertEquals("sign", new String(array.getValue()));

        MemoryBlock region = emulator.getMemory().malloc(2 * 2, true);
        Number getResult = emulator.eFunc(function(functionTable, emulator, GET_CHAR_ARRAY_REGION), pointerArg(emulator, env), handle, 1, 2, pointerArg(emulator, region.getPointer().peer));
        assertEquals(0, getResult.intValue());
        assertEquals('i', (char) region.getPointer().getShort(0));
        assertEquals('g', (char) region.getPointer().getShort(2));
        region.free();

        Number elements = emulator.eFunc(function(functionTable, emulator, GET_CHAR_ARRAY_ELEMENTS), pointerArg(emulator, env), handle, 0);
        long elementsAddress = elements.longValue() & (emulator.is64Bit() ? -1L : 0xffffffffL);
        UnidbgPointer chars = UnidbgPointer.pointer(emulator, elementsAddress);
        assertNotNull(chars);
        assertEquals('s', (char) chars.getShort(0));
        assertEquals('n', (char) chars.getShort(6));
        chars.setShort(0, (short) 'S');
        Number releaseResult = emulator.eFunc(function(functionTable, emulator, RELEASE_CHAR_ARRAY_ELEMENTS), pointerArg(emulator, env), handle, pointerArg(emulator, elementsAddress), 0);
        assertEquals(0, releaseResult.intValue());
        assertEquals("Sign", new String(array.getValue()));
    }

    private static long function(UnidbgPointer functionTable, AndroidEmulator emulator, int index) {
        return functionTable.getPointer((long) index * emulator.getPointerSize()).peer;
    }

    private static Number pointerArg(AndroidEmulator emulator, long value) {
        if (emulator.is64Bit()) {
            return value;
        }
        return (int) value;
    }

}
