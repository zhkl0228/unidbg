package com.github.unidbg.ios.classdump;

import com.github.unidbg.Emulator;
import com.github.unidbg.hook.BaseHook;
import com.github.unidbg.ios.URLibraryFile;
import com.github.unidbg.ios.objc.ObjC;
import com.github.unidbg.ios.struct.objc.ObjcClass;
import com.github.unidbg.ios.struct.objc.ObjcObject;
import com.github.unidbg.spi.LibraryFile;

import java.net.URL;
import java.util.Collections;

public class ClassDumper extends BaseHook implements IClassDumper {

    public static ClassDumper getInstance(Emulator<?> emulator) {
        ClassDumper classDumper = emulator.get(ClassDumper.class.getName());
        if (classDumper == null) {
            classDumper = new ClassDumper(emulator);
            emulator.set(ClassDumper.class.getName(), classDumper);
        }
        return classDumper;
    }

    private ClassDumper(Emulator<?> emulator) {
        super(emulator, "libclassdump");
    }

    @Override
    protected LibraryFile createURLibraryFile(URL url, String libName) {
        return new URLibraryFile(url, libName, null, Collections.<String>emptyList());
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
