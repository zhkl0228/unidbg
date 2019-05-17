package com.xingin.xhs;

import cn.banny.auxiliary.Inspector;
import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.LibraryResolver;
import cn.banny.unidbg.Module;
import cn.banny.unidbg.arm.ARMEmulator;
import cn.banny.unidbg.arm.HookStatus;
import cn.banny.unidbg.file.FileIO;
import cn.banny.unidbg.file.IOResolver;
import cn.banny.unidbg.hook.ReplaceCallback;
import cn.banny.unidbg.hook.xhook.IxHook;
import cn.banny.unidbg.hook.xhook.XHookImpl;
import cn.banny.unidbg.linux.android.AndroidARMEmulator;
import cn.banny.unidbg.linux.android.AndroidResolver;
import cn.banny.unidbg.linux.android.dvm.*;
import cn.banny.unidbg.linux.file.ByteArrayFileIO;
import cn.banny.unidbg.memory.Memory;
import cn.banny.unidbg.pointer.UnicornPointer;
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
        return new AndroidResolver(23);
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
        emulator.getMemory().setCallInitFunction();
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
        /*xHook.register("libshield.so", "__aeabi_memcpy", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator emulator, long originFunction) {
                Unicorn unicorn = emulator.getUnicorn();
                Pointer dest = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                Pointer src = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                int length = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
                Inspector.inspect(src.getByteArray(0, length), "__aeabi_memcpy dest=" + dest);
                return HookStatus.RET(unicorn, originFunction);
            }
        });*/
        xHook.register("libshield.so", "strcmp", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator emulator, long originFunction) {
                Unicorn unicorn = emulator.getUnicorn();
                Pointer src = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                Pointer dest = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                String str = dest.getString(0);
                Inspector.inspect(src.getByteArray(0, str.length()), "strcmp dest=" + str);
                return HookStatus.RET(unicorn, originFunction);
            }
        });
        xHook.refresh();

        DvmClass Chain = vm.resolveClass("okhttp3/Interceptor$Chain");
        long start = System.currentTimeMillis();
//        emulator.traceCode();
//        emulator.attach().addBreakPoint(null, 0x400259a8);
//        emulator.traceWrite(0xbffff504L, 0xbffff504L + 4);
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
    public DvmObject callObjectMethodV(BaseVM vm, DvmObject dvmObject, String signature, VaList vaList) {
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
                byte[] bytes = ("channel=Xiaomicursor_score=deviceId=e3480298-0835-355d-8972-bdce279963fcdevice_fingerprint=201905131833071ecc9d2a55804f47292bdd7406cf7ec201e39595e683d961device_fingerprint1=201905131833071ecc9d2a55804f47292bdd7406cf7ec201e39595e683d961geo=eyJsYXRpdHVkZSI6MC4wMDAwMDAsImxvbmdpdHVkZSI6MC4wMDAwMDB9\n" +
                        "lang=ennote_index=0oid=homefeed_recommendplatform=androidrefresh_type=1sid=session.1557743689143267176190sign=03c10ccc41146a7728aa4ef604ac1bcdt=1557744164trace_id=9265ef6b-b869-3bd9-97c5-3214a93ff85durl=/api/sns/v6/homefeedversionName=5.44.0\n").getBytes();
                return new ByteArray(bytes);
            case "okhttp3/Request$Builder->header(Ljava/lang/String;Ljava/lang/String;)Lokhttp3/Request$Builder;":
                StringObject name = vaList.getObject(0);
                StringObject value = vaList.getObject(4);
                System.err.println("okhttp3/Request$Builder->header name=" + name.getValue() + ", value=" + value.getValue());
                return dvmObject;
            case "okhttp3/Request$Builder->build()Lokhttp3/Request;":
                clazz = vm.resolveClass("okhttp3/Request");
                return clazz.newObject(null);
            case "okhttp3/Interceptor$Chain->proceed(Lokhttp3/Request;)Lokhttp3/Response;":
                clazz = vm.resolveClass("okhttp3/Response");
                return clazz.newObject(null);
        }

        return super.callObjectMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public int callIntMethodV(BaseVM vm, DvmObject dvmObject, String signature, VaList vaList) {
        if ("okhttp3/Response->code()I".equals(signature)) {
            return 200;
        }

        return super.callIntMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public FileIO resolve(File workDir, String pathname, int oflags) {
        if (("proc/" + emulator.getPid() + "/status").equals(pathname)) {
            return new ByteArrayFileIO(oflags, pathname, "TracerPid:\t0\n".getBytes());
        }
        return null;
    }
}
