package com.github.unidbg.ios.classdump;

import com.github.unidbg.Emulator;
import com.github.unidbg.Symbol;
import com.github.unidbg.hook.BaseHook;
import com.github.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class ClassDumper extends BaseHook implements IClassDumper {

    public static ClassDumper getInstance(Emulator emulator) {
        ClassDumper classDumper = emulator.get(ClassDumper.class.getName());
        if (classDumper == null) {
            try {
                classDumper = new ClassDumper(emulator);
                emulator.set(ClassDumper.class.getName(), classDumper);
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }
        return classDumper;
    }

    private final Symbol _dumpClass;

    private ClassDumper(Emulator emulator) throws IOException {
        super(emulator, "libclassdump");

        _dumpClass = module.findSymbolByName("_dumpClass", false);
        if (_dumpClass == null) {
            throw new IllegalStateException("_dumpClass is null");
        }
    }

    @Override
    public String dumpClass(String className) {
        byte[] buf = new byte[0x4000];
        Number[] numbers = _dumpClass.call(emulator, className, buf, buf.length);
        if (numbers.length != 3) {
            throw new IllegalStateException("numbers length=" + numbers.length);
        }
        int size = numbers[0].intValue();
        Pointer pointer = UnicornPointer.pointer(emulator, numbers[2].longValue());
        assert pointer != null;
        if (size == 0) { // dump failed
            throw new IllegalArgumentException(pointer.getString(0));
        }
        buf = pointer.getByteArray(0, size);
        return new String(buf, StandardCharsets.UTF_8);
    }
}
