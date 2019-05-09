package com.kuaishou;

import cn.banny.emulator.LibraryResolver;
import cn.banny.emulator.Module;
import cn.banny.emulator.arm.ARMEmulator;
import cn.banny.emulator.file.FileIO;
import cn.banny.emulator.file.IOResolver;
import cn.banny.emulator.linux.android.AndroidARMEmulator;
import cn.banny.emulator.linux.android.AndroidResolver;
import cn.banny.emulator.linux.android.dvm.*;
import cn.banny.emulator.memory.Memory;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.File;
import java.io.IOException;

public class KuaiShouSign extends AbstractJni implements IOResolver {

    private static final String APP_PACKAGE_NAME = "com.smile.gifmaker";

    private static LibraryResolver createLibraryResolver() {
        return new AndroidResolver(19);
    }

    private static ARMEmulator createARMEmulator() {
        return new AndroidARMEmulator(APP_PACKAGE_NAME);
    }

    private final ARMEmulator emulator;
    private final VM vm;

    private final DvmClass CPUJni;

    private static final String APK_PATH = "src/test/resources/app/kuaishou6.2.3.8614.apk";

    private final Module module;

    private final byte[] signature;

    private KuaiShouSign() throws IOException {
        emulator = createARMEmulator();
        emulator.getSyscallHandler().addIOResolver(this);
        System.out.println("== init ===");

        final Memory memory = emulator.getMemory();
        memory.setLibraryResolver(createLibraryResolver());
        memory.setCallInitFunction();

        vm = emulator.createDalvikVM(new File(APK_PATH));
        DalvikModule dm = vm.loadLibrary("core", false);
        dm.callJNI_OnLoad(emulator);
        module = dm.getModule();

        CPUJni = vm.resolveClass("com/yxcorp/gifshow/util/CPU");

        try {
            this.signature = Hex.decodeHex("3082024F308201B8A00302010202044E269662300D06092A864886F70D0101050500306B310B300906035504061302434E3110300E060355040813076265696A696E673110300E060355040713076265696A696E6731133011060355040A130A686563616F2E696E666F31133011060355040B130A686563616F2E696E666F310E300C0603550403130563616F68653020170D3131303732303038343833345A180F32303636303432323038343833345A306B310B300906035504061302434E3110300E060355040813076265696A696E673110300E060355040713076265696A696E6731133011060355040A130A686563616F2E696E666F31133011060355040B130A686563616F2E696E666F310E300C0603550403130563616F686530819F300D06092A864886F70D010101050003818D003081890281810093BCE2A30779500E3A3160CE5B557F3FA34DF50DF25AC1AE38C181C8AD94E4709D00AFBC532D27CCFD4A92C8F1BD5B19C1F04F37B8230020035E33EB39DE2D482AD4C043F251FB08007CB3EAC4A348E140A817784195F0FBAFC7480C90F76EF966D220ABD9C4AB3D246276C98CE6D77A7FCC4F451AE89EB387D9BFF521898D970203010001300D06092A864886F70D0101050500038181001CE4EB9F42D76DFC4E0F5DA07BC3EFAE2CF98B47A39790D35407F3AEB6B554CADD65E84C7252046B3AB72B2DFC86F0892E28FEE3E6E4E801093E3A4F29BC560762D33839CEB29385583DED64548F245977D61925543DDA7AC3D34E8153A88F9846F446FF96D4877AD808280BBD7C43B9BF5FEEA3DD8D6BD179BC8CF29F949163".toCharArray());
        } catch (DecoderException e) {
            throw new IllegalStateException(e);
        }
    }

    private void destroy() throws IOException {
        emulator.close();
        System.out.println("module=" + module);
        System.out.println("== destroy ===");
    }

    public static void main(String[] args) throws Exception {
        KuaiShouSign test = new KuaiShouSign();
        test.sign();
        test.destroy();
    }

    private void sign() {
        vm.setJni(this);
        Logger.getLogger("cn.banny.emulator.AbstractEmulator").setLevel(Level.DEBUG);
        String str = "app=0appver=6.2.3.8614c=ALI_CPD,17client_key=3c2cd3f3contactData=7A9IqsDstz815+zxGyC1+XgougsArgtFUPBRYcRwUhcjwTsafJBmYnLZgLc5l4g7sjINLj0nrXFq1CCsFHteQSpac+959kD0yYEJyGzukSqMQGayQCue397jX98gp0NPU26waWGh+JWMaYnZG/F1Sg==country_code=CNdid=ANDROID_9fb7792f6142ea63did_gt=1553767215144ftt=hotfix_ver=isp=iuid=iv=5okP62w8Yl7WHiG6kpf=ANDROID_PHONEkpn=KUAISHOUlanguage=zh-cnlat=40.054041lon=116.298517max_memory=192mod=LGE(Nexus 5)net=WIFIoc=ALI_CPD,17os=androidsys=ANDROID_6.0.1token=f68245ccc1344489894f963248cc3501-1082592150ud=1082592150ver=6.2";

//        emulator.traceCode();
//        emulator.attach().addBreakPoint(null, 0x40001278);
        DvmObject context = vm.resolveClass("com/yxcorp/gifshow/App").newObject(null);
        Number ret = CPUJni.callStaticJniMethod(emulator, "getClock(Ljava/lang/Object;[BI)Ljava/lang/String;",
                context,
                vm.addLocalObject(new ByteArray(str.getBytes())), 23);
        long hash = ret.intValue() & 0xffffffffL;
        StringObject obj = vm.getObject(hash);
        vm.deleteLocalRefs();
        System.out.println(obj.getValue());
    }

    @Override
    public FileIO resolve(File workDir, String pathname, int oflags) {
        return null;
    }

    @Override
    public DvmObject callObjectMethodV(VM vm, DvmObject dvmObject, String signature, String methodName, String args, VaList vaList) {
        switch (signature) {
            case "com/yxcorp/gifshow/App->getPackageName()Ljava/lang/String;":
                return new StringObject(vm, APP_PACKAGE_NAME);
            case "com/yxcorp/gifshow/App->getPackageManager()Landroid/content/pm/PackageManager;":
                return new DvmObject<Object>(vm.resolveClass("android/content/pm/PackageManager"), null);
            case "android/content/pm/PackageManager->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;":
                StringObject packageName = vaList.getObject(0);
                int flags = vaList.getInt(4);
                System.err.println("getPackageInfo packageName=" + packageName.getValue() + ", flags=" + flags);
                return vm.resolveClass("android/content/pm/PackageInfo").newObject(packageName.getValue());
            case "android/content/pm/Signature->toByteArray()[B":
                return new ByteArray(this.signature);
        }

        return super.callObjectMethodV(vm, dvmObject, signature, methodName, args, vaList);
    }

    @Override
    public DvmObject getObjectField(VM vm, DvmObject dvmObject, String signature) {
        if ("android/content/pm/PackageInfo->signatures:[Landroid/content/pm/Signature;".equals(signature)) {
            String packageName = (String) dvmObject.getValue();
            System.err.println("PackageInfo signatures packageName=" + packageName);
            DvmObject sig = vm.resolveClass("android/content/pm/Signature").newObject(null);
            return new ArrayObject(sig);
        }
        return super.getObjectField(vm, dvmObject, signature);
    }
}