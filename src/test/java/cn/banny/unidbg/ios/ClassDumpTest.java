package cn.banny.unidbg.ios;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.LibraryResolver;
import cn.banny.unidbg.android.EmulatorTest;
import cn.banny.unidbg.ios.classdump.ClassDumper;
import cn.banny.unidbg.ios.classdump.IClassDumper;

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
        String objcClass = classDumper.dumpClass("BootstrapTest");
        System.out.println(objcClass);
    }

}
