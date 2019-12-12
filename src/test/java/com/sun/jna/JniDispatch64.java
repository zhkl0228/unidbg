package com.sun.jna;

import cn.banny.auxiliary.Inspector;
import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.LibraryResolver;
import cn.banny.unidbg.Module;
import cn.banny.unidbg.Symbol;
import cn.banny.unidbg.arm.ARMEmulator;
import cn.banny.unidbg.arm.HookStatus;
import cn.banny.unidbg.arm.context.RegisterContext;
import cn.banny.unidbg.debugger.DebuggerType;
import cn.banny.unidbg.hook.ReplaceCallback;
import cn.banny.unidbg.hook.hookzz.HookEntryInfo;
import cn.banny.unidbg.hook.hookzz.HookZz;
import cn.banny.unidbg.hook.hookzz.IHookZz;
import cn.banny.unidbg.hook.hookzz.WrapCallback;
import cn.banny.unidbg.hook.whale.IWhale;
import cn.banny.unidbg.hook.whale.Whale;
import cn.banny.unidbg.hook.xhook.IxHook;
import cn.banny.unidbg.linux.android.AndroidARM64Emulator;
import cn.banny.unidbg.linux.android.AndroidResolver;
import cn.banny.unidbg.linux.android.XHookImpl;
import cn.banny.unidbg.linux.android.dvm.*;
import cn.banny.unidbg.memory.Memory;
import cn.banny.unidbg.pointer.UnicornPointer;

import java.io.File;
import java.io.IOException;

public class JniDispatch64 extends AbstractJni {

    private static LibraryResolver createLibraryResolver() {
        return new AndroidResolver(23);
    }

    private static ARMEmulator createARMEmulator() {
        return new AndroidARM64Emulator("com.sun.jna");
    }

    private final ARMEmulator emulator;
    private final VM vm;
    private final Module module;

    private final DvmClass Native;

    private JniDispatch64() throws IOException {
        emulator = createARMEmulator();
        final Memory memory = emulator.getMemory();
        memory.setLibraryResolver(createLibraryResolver());
        memory.setCallInitFunction();

        vm = emulator.createDalvikVM(null);
        vm.setJni(this);
        DalvikModule dm = vm.loadLibrary(new File("src/test/resources/example_binaries/arm64-v8a/libjnidispatch.so"), false);
        dm.callJNI_OnLoad(emulator);
        this.module = dm.getModule();

        Native = vm.resolveClass("com/sun/jna/Native");
    }

    private void destroy() throws IOException {
        emulator.close();
        System.out.println("destroy");
    }

    public static void main(String[] args) throws Exception {
        JniDispatch64 test = new JniDispatch64();

        test.test();

        test.destroy();
    }

    private void test() {
        IxHook xHook = XHookImpl.getInstance(emulator);
        xHook.register("libjnidispatch.so", "malloc", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator emulator, long originFunction) {
                int size = emulator.getContext().getIntArg(0);
                System.out.println("malloc=" + size);
                return HookStatus.RET(emulator, originFunction);
            }
        });
        xHook.refresh();

        IWhale whale = Whale.getInstance(emulator);
        Symbol free = emulator.getMemory().findModule("libc.so").findSymbolByName("free");
        whale.WInlineHookFunction(free, new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator emulator, long originFunction) {
                System.out.println("WInlineHookFunction free=" + emulator.getContext().getPointerArg(0));
                return HookStatus.RET(emulator, originFunction);
            }
        });

        long start = System.currentTimeMillis();
        final int size = 0x20;
        Number ret = Native.callStaticJniMethod(emulator, "malloc(J)J", size);
        Pointer pointer = UnicornPointer.pointer(emulator, ret.intValue() & 0xffffffffL);
        assert pointer != null;
        pointer.setString(0, getClass().getName());
        vm.deleteLocalRefs();
        Inspector.inspect(pointer.getByteArray(0, size), "malloc ret=0x" + Long.toHexString(ret.longValue()) + ", offset=" + (System.currentTimeMillis() - start) + "ms");

        IHookZz hookZz = HookZz.getInstance(emulator);
        Symbol newJavaString = module.findSymbolByName("newJavaString");
        hookZz.wrap(newJavaString, new WrapCallback<RegisterContext>() {
            @Override
            public void preCall(Emulator emulator, RegisterContext ctx, HookEntryInfo info) {
                Pointer value = ctx.getPointerArg(1);
                Pointer encoding = ctx.getPointerArg(2);
                System.out.println("newJavaString value=" + value.getString(0) + ", encoding=" + encoding.getString(0));
            }
        });

        ret = Native.callStaticJniMethod(emulator, "getNativeVersion()Ljava/lang/String;");
        long hash = ret.intValue() & 0xffffffffL;
        StringObject version = vm.getObject(hash);
        vm.deleteLocalRefs();
        System.out.println("getNativeVersion version=" + version.getValue() + ", offset=" + (System.currentTimeMillis() - start) + "ms");

        ret = Native.callStaticJniMethod(emulator, "getAPIChecksum()Ljava/lang/String;");
        hash = ret.intValue() & 0xffffffffL;
        StringObject checksum = vm.getObject(hash);
        vm.deleteLocalRefs();
        System.out.println("getAPIChecksum checksum=" + checksum.getValue() + ", offset=" + (System.currentTimeMillis() - start) + "ms");

        emulator.attach(DebuggerType.GDB_SERVER);
        ret = Native.callStaticJniMethod(emulator, "sizeof(I)I", 0);
        vm.deleteLocalRefs();
        System.out.println("sizeof POINTER_SIZE=" + ret.intValue() + ", offset=" + (System.currentTimeMillis() - start) + "ms");
    }

    @Override
    public DvmObject callStaticObjectMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        if ("java/lang/System->getProperty(Ljava/lang/String;)Ljava/lang/String;".equals(signature)) {
            StringObject string = varArg.getObject(0);
            return new StringObject(vm, System.getProperty(string.getValue()));
        }

        return super.callStaticObjectMethod(vm, dvmClass, signature, varArg);
    }
}
