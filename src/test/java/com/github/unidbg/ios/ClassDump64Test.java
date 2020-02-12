package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.android.EmulatorTest;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.substrate.ISubstrate;
import com.github.unidbg.ios.classdump.ClassDumper;
import com.github.unidbg.ios.classdump.IClassDumper;
import com.github.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;

public class ClassDump64Test extends EmulatorTest {

    @Override
    protected LibraryResolver createLibraryResolver() {
        return new DarwinResolver();
    }

    @Override
    protected Emulator createARMEmulator() {
        return new DarwinARM64Emulator();
    }

    public void testClassDump() {
//        Logger.getLogger("com.github.unidbg.AbstractEmulator").setLevel(Level.DEBUG);

        MachOLoader loader = (MachOLoader) emulator.getMemory();
        loader.setCallInitFunction();
        loader.setObjcRuntime(true);
        IClassDumper classDumper = ClassDumper.getInstance(emulator);

        Module main = loader.getExecutableModule();
        Symbol _objc_getMetaClass = main.findSymbolByName("_objc_getMetaClass");
        assertNotNull(_objc_getMetaClass);
        Number ClassDump = _objc_getMetaClass.call(emulator, "ClassDump")[0];
        assertTrue(ClassDump.intValue() != 0);

        Symbol _sel_registerName = main.findSymbolByName("_sel_registerName");
        assertNotNull(_sel_registerName);
        Number my_dump_class = _sel_registerName.call(emulator, "my_dump_class:")[0];
        assertTrue(my_dump_class.intValue() != 0);

//        Logger.getLogger("com.github.unidbg.ios.ARM64SyscallHandler").setLevel(Level.DEBUG);
//        Logger.getLogger("com.github.unidbg.ios.Dyld64").setLevel(Level.DEBUG);
        ISubstrate substrate = Substrate.getInstance(emulator);
//        Module libSubstrate = emulator.getMemory().findModule("CydiaSubstrate");
//        emulator.attach(libSubstrate.base, libSubstrate.base + libSubstrate.size).addBreakPoint(libSubstrate, 0x0000000000002988);
        substrate.hookMessageEx(UnicornPointer.pointer(emulator, ClassDump), UnicornPointer.pointer(emulator, my_dump_class), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator emulator, long originFunction) {
                RegisterContext context = emulator.getContext();
                Pointer id = context.getPointerArg(0);
                Pointer SEL = context.getPointerArg(1);
                Pointer name = context.getPointerArg(2);
                System.err.println("my_dump_class id=" + id + ", SEL=" + SEL + ", name=" + name.getString(0));
                name.setString(0, "NSDate");
                return HookStatus.RET(emulator, originFunction);
            }
        });

        String objcClass = classDumper.dumpClass("NSLocale");
        System.out.println(objcClass);
    }

    public static void main(String[] args) throws Exception {
        ClassDump64Test test = new ClassDump64Test();
        test.setUp();
        test.testClassDump();
        test.tearDown();
    }

}
