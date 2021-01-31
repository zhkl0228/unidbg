package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.arm.ARMEmulator;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.hook.HookContext;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.substrate.ISubstrate;
import com.github.unidbg.ios.classdump.ClassDumper;
import com.github.unidbg.ios.classdump.IClassDumper;
import com.github.unidbg.ios.hook.Substrate;
import com.github.unidbg.ios.objc.ObjC;
import com.github.unidbg.ios.struct.objc.ObjcClass;
import com.github.unidbg.ios.struct.objc.ObjcObject;
import com.sun.jna.Pointer;

import java.io.File;

public class ClassDumpTest extends EmulatorTest<ARMEmulator<DarwinFileIO>> {

    @Override
    protected LibraryResolver createLibraryResolver() {
        return new DarwinResolver();
    }

    @Override
    protected ARMEmulator<DarwinFileIO> createARMEmulator() {
        return DarwinEmulatorBuilder.for32Bit()
                .setRootDir(new File("target/rootfs/classdump"))
                .build();
    }

    public void testIgnore() {
    }

    private void processClassDump() {
        MachOLoader loader = (MachOLoader) emulator.getMemory();
        loader.setObjcRuntime(true);
        IClassDumper classDumper = ClassDumper.getInstance(emulator);
        ISubstrate substrate = Substrate.getInstance(emulator);

        ObjC objc = ObjC.getInstance(emulator);
        ObjcClass oClassDump = objc.getClass("ClassDump");
        assertNotNull(oClassDump);
        substrate.hookMessageEx(oClassDump.getMeta(), objc.registerName("my_dump_class:"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                Pointer id = context.getPointerArg(0);
                Pointer SEL = context.getPointerArg(1);
                Pointer name = context.getPointerArg(2);
                String className = name.getString(0);
                context.push(className);
                if (!"NSLocale".equals(className)) {
                    return HookStatus.RET(emulator, originFunction);
                }

                ObjcObject obj = ObjcObject.create(emulator, id);
                System.err.println("my_dump_class id=" + id + ", SEL=" + SEL + ", name=" + className + ", className=" + obj.getObjClass().getName());
                name.setString(0, "NSDate");
                return HookStatus.RET(emulator, originFunction);
            }
            @Override
            public void postCall(Emulator<?> emulator, HookContext context) {
                System.err.println("postCall className=" + context.pop());
            }
        }, true);

        String objcClass = classDumper.dumpClass("NSLocale");
        System.out.println(objcClass);

        assertTrue(oClassDump.getMeta().isMetaClass());
        System.out.println("className=" + oClassDump.getName() + ", metaClassName=" + oClassDump.getMeta().getName());

        ObjcObject str = oClassDump.callObjc("my_dump_class:", "NSDictionary");
        System.out.println(str.getDescription());

        classDumper.searchClass("ClassD");
    }

    public static void main(String[] args) throws Exception {
        ClassDumpTest test = new ClassDumpTest();
        test.setUp();
        test.processClassDump();
        test.tearDown();
    }

}
