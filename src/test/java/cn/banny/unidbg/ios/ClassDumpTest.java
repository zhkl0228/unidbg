package cn.banny.unidbg.ios;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.LibraryResolver;
import cn.banny.unidbg.Module;
import cn.banny.unidbg.Symbol;
import cn.banny.unidbg.android.EmulatorTest;
import cn.banny.unidbg.arm.HookStatus;
import cn.banny.unidbg.arm.context.RegisterContext;
import cn.banny.unidbg.hook.ReplaceCallback;
import cn.banny.unidbg.hook.substrate.ISubstrate;
import cn.banny.unidbg.ios.classdump.ClassDumper;
import cn.banny.unidbg.ios.classdump.IClassDumper;
import cn.banny.unidbg.pointer.UnicornPointer;
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

    public void testClassDump() throws Exception {
        MachOLoader loader = (MachOLoader) emulator.getMemory();
        loader.setCallInitFunction();
        loader.setObjcRuntime(true);
        IClassDumper classDumper = ClassDumper.getInstance(emulator);

        ISubstrate substrate = Substrate.getInstance(emulator);

        Module main = loader.getExecutableModule();
        Symbol _objc_getMetaClass = main.findSymbolByName("_objc_getMetaClass");
        assertNotNull(_objc_getMetaClass);
        Number ClassDump = _objc_getMetaClass.call(emulator, "ClassDump")[0];
        assertTrue(ClassDump.intValue() != 0);

        Symbol _sel_registerName = main.findSymbolByName("_sel_registerName");
        assertNotNull(_sel_registerName);
        Number my_dump_class = _sel_registerName.call(emulator, "my_dump_class:")[0];
        assertTrue(my_dump_class.intValue() != 0);

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
        ClassDumpTest test = new ClassDumpTest();
        test.setUp();
        test.testClassDump();
        test.tearDown();
    }

}
