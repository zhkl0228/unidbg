package com.github.unidbg.ios.classdump;

import com.github.unidbg.Emulator;
import com.github.unidbg.hook.BaseHook;
import com.github.unidbg.ios.objc.ObjC;
import com.github.unidbg.ios.struct.objc.ObjcClass;
import com.github.unidbg.ios.struct.objc.ObjcObject;
import com.sun.jna.Pointer;

import java.io.IOException;

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

    private ClassDumper(Emulator emulator) throws IOException {
        super(emulator, "libclassdump");
    }

    @Override
    public String dumpClass(String className) {
        ObjC objc = ObjC.getInstance(emulator);
        ObjcClass oClassDump = objc.getClass("ClassDump");
        Pointer pointer = oClassDump.call(emulator, "my_dump_class:", className);
        if (pointer == null) {
            return null;
        } else {
            ObjcObject str = ObjcObject.create(emulator, pointer);
            return str.call(emulator, "UTF8String").getString(0);
        }
    }
}
