package com.sun.jna;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.backend.HypervisorFactory;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.hook.HookContext;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.hookzz.Dobby;
import com.github.unidbg.hook.hookzz.HookEntryInfo;
import com.github.unidbg.hook.hookzz.IHookZz;
import com.github.unidbg.hook.hookzz.InstrumentCallback;
import com.github.unidbg.hook.whale.IWhale;
import com.github.unidbg.hook.whale.Whale;
import com.github.unidbg.hook.xhook.IxHook;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.XHookImpl;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.jni.ProxyClassFactory;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.utils.Inspector;

import java.io.File;
import java.io.IOException;

public class JniDispatch64 {

    private static LibraryResolver createLibraryResolver() {
        return new AndroidResolver(23);
    }

    private static AndroidEmulator createARMEmulator() {
        return AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.sun.jna")
                .addBackendFactory(new HypervisorFactory(true))
                .build();
    }

    private final AndroidEmulator emulator;
    private final Module module;

    private final DvmClass cNative;

    private JniDispatch64() {
        emulator = createARMEmulator();
        final Memory memory = emulator.getMemory();
        memory.setLibraryResolver(createLibraryResolver());

        VM vm = emulator.createDalvikVM();
        vm.setDvmClassFactory(new ProxyClassFactory());
        vm.setVerbose(true);
        DalvikModule dm = vm.loadLibrary(new File("unidbg-android/src/test/resources/example_binaries/arm64-v8a/libjnidispatch.so"), false);
        dm.callJNI_OnLoad(emulator);
        this.module = dm.getModule();

        cNative = vm.resolveClass("com/sun/jna/Native");

        Symbol __system_property_get = module.findSymbolByName("__system_property_get", true);
        MemoryBlock block = null;
        try {
            block = memory.malloc(0x10, false);
            Number ret = __system_property_get.call(emulator, "ro.build.version.sdk", block.getPointer());
            System.out.println("sdk=" + new String(block.getPointer().getByteArray(0, ret.intValue())));
        } finally {
            if (block != null) {
                block.free();
            }
        }
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
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                int size = context.getIntArg(0);
                System.out.println("malloc=" + size);
                context.push(size);
                return HookStatus.RET(emulator, originFunction);
            }
            @Override
            public void postCall(Emulator<?> emulator, HookContext context) {
                System.out.println("malloc=" + context.pop() + ", ret=" + context.getPointerArg(0));
            }
        });
        xHook.refresh();

        IWhale whale = Whale.getInstance(emulator);
        Symbol free = emulator.getMemory().findModule("libc.so").findSymbolByName("free");
        whale.inlineHookFunction(free, new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                System.out.println("WInlineHookFunction free=" + emulator.getContext().getPointerArg(0));
                return HookStatus.RET(emulator, originFunction);
            }
        });

        long start = System.currentTimeMillis();
        final int size = 0x20;
        Number ret = cNative.callStaticJniMethodLong(emulator, "malloc(J)J", size);
        Pointer pointer = UnidbgPointer.pointer(emulator, ret.intValue() & 0xffffffffL);
        assert pointer != null;
        pointer.setString(0, getClass().getName());
        Inspector.inspect(pointer.getByteArray(0, size), "malloc ret=0x" + Long.toHexString(ret.longValue()) + ", offset=" + (System.currentTimeMillis() - start) + "ms");

        IHookZz hookZz = Dobby.getInstance(emulator);
        Symbol newJavaString = module.findSymbolByName("newJavaString");
        hookZz.instrument(newJavaString, new InstrumentCallback<RegisterContext>() {
            @Override
            public void dbiCall(Emulator<?> emulator, RegisterContext ctx, HookEntryInfo info) {
                Pointer value = ctx.getPointerArg(1);
                Pointer encoding = ctx.getPointerArg(2);
                System.out.println("newJavaString value=" + value.getString(0) + ", encoding=" + encoding.getString(0));
            }
        });

        DvmObject<?> version = cNative.callStaticJniMethodObject(emulator, "getNativeVersion()Ljava/lang/String;");
        System.out.println("getNativeVersion version=" + version.getValue() + ", offset=" + (System.currentTimeMillis() - start) + "ms");

        DvmObject<?> checksum = cNative.callStaticJniMethodObject(emulator, "getAPIChecksum()Ljava/lang/String;");
        System.out.println("getAPIChecksum checksum=" + checksum.getValue() + ", offset=" + (System.currentTimeMillis() - start) + "ms");

//        emulator.attach(DebuggerType.ANDROID_SERVER_V7);
        ret = cNative.callStaticJniMethodInt(emulator, "sizeof(I)I", 0);
        System.out.println("sizeof POINTER_SIZE=" + ret.intValue() + ", offset=" + (System.currentTimeMillis() - start) + "ms");
    }
}
