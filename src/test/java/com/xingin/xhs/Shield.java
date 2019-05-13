package com.xingin.xhs;

import cn.banny.auxiliary.Inspector;
import cn.banny.emulator.Emulator;
import cn.banny.emulator.LibraryResolver;
import cn.banny.emulator.Module;
import cn.banny.emulator.arm.ARMEmulator;
import cn.banny.emulator.arm.HookStatus;
import cn.banny.emulator.file.FileIO;
import cn.banny.emulator.file.IOResolver;
import cn.banny.emulator.hook.ReplaceCallback;
import cn.banny.emulator.hook.xhook.IxHook;
import cn.banny.emulator.hook.xhook.XHookImpl;
import cn.banny.emulator.linux.android.AndroidARMEmulator;
import cn.banny.emulator.linux.android.AndroidResolver;
import cn.banny.emulator.linux.android.dvm.*;
import cn.banny.emulator.linux.file.ByteArrayFileIO;
import cn.banny.emulator.memory.Memory;
import cn.banny.emulator.pointer.UnicornPointer;
import com.sun.jna.Pointer;
import unicorn.ArmConst;
import unicorn.Unicorn;

import java.io.File;
import java.io.IOException;

/**
 * Created by apple on 2019/4/23.
 */
public class Shield extends AbstractJni implements IOResolver {

    private static LibraryResolver createLibraryResolver() {
        return new AndroidResolver(19);
    }

    private static ARMEmulator createARMEmulator() {
        return new AndroidARMEmulator("com.xingin.xhs");
    }

    private final ARMEmulator emulator;
    private final VM vm;
    private final Module module;
    private final DvmClass RedHttpInterceptor;

    private Shield() throws IOException {
        emulator = createARMEmulator();
        emulator.getSyscallHandler().addIOResolver(this);
//        emulator.traceCode();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(createLibraryResolver());
        vm = emulator.createDalvikVM(new File("src/test/resources/app/com.xingin.xhs_5.44.0.apk"));

        vm.setJni(this);
        DalvikModule dm = vm.loadLibrary("shield",false);

        dm.callJNI_OnLoad(emulator);
        module = dm.getModule();

//        emulator.getMemory().runLastThread(TimeUnit.SECONDS.toMicros(3));

        RedHttpInterceptor = vm.resolveClass("com/xingin/shield/http/RedHttpInterceptor");
        RedHttpInterceptor.callStaticJniMethod(emulator,"initializeNative()V");
        vm.deleteLocalRefs();
        System.out.println("initializeNative ok");
    }

    private void request() {
        IxHook xHook = XHookImpl.getInstance(emulator);
        xHook.register("libshield.so", "strlen", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator emulator, long originFunction) {
                Pointer pointer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                System.out.println("strlen=" + pointer.getString(0));
                return HookStatus.RET(emulator.getUnicorn(), originFunction);
            }
        });
        xHook.register("libshield.so", "memmove", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator emulator, long originFunction) {
                Unicorn unicorn = emulator.getUnicorn();
                Pointer dest = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                Pointer src = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                int length = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
                Inspector.inspect(src.getByteArray(0, length), "memmove dest=" + dest);
                return HookStatus.RET(unicorn, originFunction);
            }
        });
        xHook.register("libshield.so", "memcpy", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator emulator, long originFunction) {
                Unicorn unicorn = emulator.getUnicorn();
                Pointer dest = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                Pointer src = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                int length = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
                Inspector.inspect(src.getByteArray(0, length), "memcpy dest=" + dest);
                return HookStatus.RET(unicorn, originFunction);
            }
        });
        xHook.refresh();

        DvmClass Chain = vm.resolveClass("okhttp3/Interceptor$Chain");
        long start = System.currentTimeMillis();
        Number ret = RedHttpInterceptor.newObject(null).callJniMethod(emulator, "process(Lokhttp3/Interceptor$Chain;)Lokhttp3/Response;", Chain.newObject(null));
        long hash = ret.intValue() & 0xffffffffL;
        DvmObject obj = vm.getObject(hash);
        vm.deleteLocalRefs();
        System.out.println("process ret=0x" + Integer.toHexString(ret.intValue()) + ", obj=" + obj.getValue() + ", offset=" + (System.currentTimeMillis() - start) + "ms");
    }

    public static void main(String[] args) throws IOException {
        Shield shield = new Shield();
        shield.request();
        shield.destroy();
    }

    private void destroy() throws IOException {
        emulator.close();
        System.out.println("module=" + module);
    }

    @Override
    public DvmObject callObjectMethodV(VM vm, DvmObject dvmObject, String signature, String methodName, String args, VaList vaList) {
        switch (signature) {
            case "com/xingin/shield/http/RedHttpInterceptor->deviceId()Ljava/lang/String;":
                return new StringObject(vm,"e3480298-0835-355d-8972-bdce279963fc");
            case "okhttp3/Interceptor$Chain->request()Lokhttp3/Request;":
                DvmClass clazz = vm.resolveClass("okhttp3/Request");
                return clazz.newObject(null);
            case "okhttp3/Request->newBuilder()Lokhttp3/Request$Builder;":
                clazz = vm.resolveClass("okhttp3/Request$Builder");
                return clazz.newObject(null);
            case "com/xingin/shield/http/RedHttpInterceptor->getBytesOfParams(Lokhttp3/Request;)[B":
                byte[] data = new byte[256]; // TODO 生成真实的请求数据
                return new ByteArray(data);
            case "okhttp3/Request$Builder->header(Ljava/lang/String;Ljava/lang/String;)Lokhttp3/Request$Builder;":
                StringObject name = vaList.getObject(0);
                StringObject value = vaList.getObject(4);
                System.out.println("okhttp3/Request$Builder->header name=" + name.getValue() + ", value=" + value.getValue());
                return dvmObject;
            case "okhttp3/Request$Builder->build()Lokhttp3/Request;":
                clazz = vm.resolveClass("okhttp3/Request");
                return clazz.newObject(null);
            case "okhttp3/Interceptor$Chain->proceed(Lokhttp3/Request;)Lokhttp3/Response;":
                clazz = vm.resolveClass("okhttp3/Response");
                return clazz.newObject(null);
        }

        return super.callObjectMethodV(vm, dvmObject, signature, methodName, args, vaList);
    }

    @Override
    public int callIntMethodV(BaseVM vm, DvmObject dvmObject, String signature, String methodName, String args, VaList vaList) {
        if ("okhttp3/Response->code()I".equals(signature)) {
            return 200;
        }

        return super.callIntMethodV(vm, dvmObject, signature, methodName, args, vaList);
    }

    @Override
    public FileIO resolve(File workDir, String pathname, int oflags) {
        if (("proc/" + emulator.getPid() + "/status").equals(pathname)) {
            return new ByteArrayFileIO(oflags, pathname, "TracerPid:\t0\n".getBytes());
        }
        return null;
    }
}
