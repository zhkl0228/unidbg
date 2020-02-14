package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.android.EmulatorTest;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.substrate.ISubstrate;
import com.github.unidbg.ios.classdump.ClassDumper;
import com.github.unidbg.ios.classdump.IClassDumper;
import com.github.unidbg.ios.objc.ObjC;
import com.github.unidbg.ios.struct.objc.ObjcClass;
import com.github.unidbg.ios.struct.objc.ObjcObject;
import com.sun.jna.Pointer;

public class ClassDumpTest extends EmulatorTest {

    @Override
    protected LibraryResolver createLibraryResolver() {
        return new DarwinResolver();
    }

    @Override
    protected Emulator createARMEmulator() {
        return new DarwinARMEmulator();
    }

    public void testClassDump() {
        MachOLoader loader = (MachOLoader) emulator.getMemory();
        loader.setCallInitFunction();
        loader.setObjcRuntime(true);
        IClassDumper classDumper = ClassDumper.getInstance(emulator);

        ISubstrate substrate = Substrate.getInstance(emulator);

        ObjC objc = ObjC.getInstance(emulator);
        ObjcClass oClassDump = objc.getClass("ClassDump");
        substrate.hookMessageEx(oClassDump.getMeta(), objc.registerName("my_dump_class:"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator emulator, long originFunction) {
                RegisterContext context = emulator.getContext();
                Pointer id = context.getPointerArg(0);
                Pointer SEL = context.getPointerArg(1);
                Pointer name = context.getPointerArg(2);
                ObjcObject obj = ObjcObject.create(id);
                System.err.println("my_dump_class id=" + id + ", SEL=" + SEL + ", name=" + name.getString(0) + ", className=" + obj.getObjClass().getName());
                name.setString(0, "NSDate");
                return HookStatus.RET(emulator, originFunction);
            }
        });

        String objcClass = classDumper.dumpClass("NSLocale");
        System.out.println(objcClass);

        assertTrue(oClassDump.getMeta().isMetaClass());
        System.out.println("className=" + oClassDump.getName() + ", metaClassName=" + oClassDump.getMeta().getName());
    }

    public static void main(String[] args) throws Exception {
        ClassDumpTest test = new ClassDumpTest();
        test.setUp();
        test.testClassDump();
        test.tearDown();
    }

}
