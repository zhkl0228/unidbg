package com.github.unidbg.ios.classdump;

import com.github.unidbg.Emulator;
import com.github.unidbg.hook.BaseHook;
import com.github.unidbg.ios.objc.ObjC;
import com.github.unidbg.ios.struct.objc.ObjcClass;
import com.github.unidbg.ios.struct.objc.ObjcObject;

import java.io.IOException;

public class ClassDumper extends BaseHook implements IClassDumper {

    public static ClassDumper getInstance(Emulator<?> emulator) {
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

    private ClassDumper(Emulator<?> emulator) throws IOException {
        super(emulator, "libclassdump");
    }

    @Override
    public String dumpClass(String className) {
        ObjC objc = ObjC.getInstance(emulator);
        ObjcClass oClassDump = objc.getClass("ClassDump");
        ObjcObject str = oClassDump.callObjc("my_dump_class:", className);
        return str == null ? null : str.getDescription();
    }

    @Override
    public void searchClass(String keywords) {
        ObjC objc = ObjC.getInstance(emulator);
        ObjcClass oClassDump = objc.getClass("ClassDump");
        oClassDump.callObjc("search_class:", keywords);
    }
}
