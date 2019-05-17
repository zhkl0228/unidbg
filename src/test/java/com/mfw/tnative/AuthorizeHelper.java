package com.mfw.tnative;

import cn.banny.unidbg.LibraryResolver;
import cn.banny.unidbg.Module;
import cn.banny.unidbg.arm.ARMEmulator;
import cn.banny.unidbg.file.FileIO;
import cn.banny.unidbg.file.IOResolver;
import cn.banny.unidbg.linux.android.AndroidARMEmulator;
import cn.banny.unidbg.linux.android.AndroidResolver;
import cn.banny.unidbg.linux.android.dvm.*;
import cn.banny.unidbg.memory.Memory;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.File;
import java.io.IOException;

public class AuthorizeHelper extends AbstractJni implements IOResolver {

    private static final String APP_PACKAGE_NAME = "com.mfw.roadbook";

    private static LibraryResolver createLibraryResolver() {
        return new AndroidResolver(23);
    }

    private static ARMEmulator createARMEmulator() {
        return new AndroidARMEmulator(APP_PACKAGE_NAME);
    }

    private final ARMEmulator emulator;
    private final VM vm;

    private final DvmClass AuthorizeHelper;

    private static final String APK_PATH = "src/test/resources/app/mafengwo_ziyouxing.apk";

    private final Module module;

    private AuthorizeHelper() throws IOException {
        emulator = createARMEmulator();
        emulator.getSyscallHandler().addIOResolver(this);
        System.out.println("== init ===");

        final Memory memory = emulator.getMemory();
        memory.setLibraryResolver(createLibraryResolver());
        memory.setCallInitFunction();

        vm = emulator.createDalvikVM(new File(APK_PATH));
        vm.setJni(this);
        DalvikModule dm = vm.loadLibrary("mfw", false);
        dm.callJNI_OnLoad(emulator);
        module = dm.getModule();

        AuthorizeHelper = vm.resolveClass("com/mfw/tnative/AuthorizeHelper");
    }

    private void destroy() throws IOException {
        emulator.close();
        System.out.println("module=" + module);
        System.out.println("== destroy ===");
    }

    public static void main(String[] args) throws Exception {
        AuthorizeHelper test = new AuthorizeHelper();
        test.test();
        test.destroy();
    }

    private void test() {
        Logger.getLogger("cn.banny.unidbg.AbstractEmulator").setLevel(Level.DEBUG);
        String str = "GET&https%3A%2F%2Fm.mafengwo.cn%2Fnb%2Fnotify%2Freg.php&app_code%3Dcom.mfw.roadbook%26app_ver%3D9.3.7%26app_version_code%3D734%26brand%3Dxiaomi%26channel_id%3DMFW%26dev_ver%3DD1907.0%26device_id%3D00%253A81%253A3b%253A8c%253Ac4%253Afb%26device_type%3Dandroid%26getui_cid%3Ded2298df7a84b5cfba0bda07f0941e17%26getui_errorcode%3D0%26hardware_model%3Dxiaomi%25206%26has_notch%3D0%26mfwsdk_ver%3D20140507%26oauth_consumer_key%3D5%26oauth_nonce%3D1e42255c-2d49-4dd2-be63-fc139c7ee4da%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1558012774%26oauth_token%3D32292063_a78f3be14db160e12118b1fe0ec11219%26oauth_version%3D1.0%26open_udid%3D00%253A81%253A3b%253A8c%253Ac4%253Afb%26patch_ver%3D3.0%26push_open%3D1%26screen_height%3D960%26screen_scale%3D1.5%26screen_width%3D540%26sys_ver%3D5.1.1%26time_offset%3D480%26uid%3D32292063%26x_auth_mode%3Dclient_auth";
        DvmObject context = vm.resolveClass("android/content/Context").newObject(null);
        Number ret = AuthorizeHelper.newObject(null).callJniMethod(emulator, "xPreAuthencode(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
                context, vm.addLocalObject(new StringObject(vm, str)), vm.addLocalObject(new StringObject(vm, APP_PACKAGE_NAME)));
        long hash = ret.intValue() & 0xffffffffL;
        StringObject obj = vm.getObject(hash);
        vm.deleteLocalRefs();
        System.out.println(obj.getValue());
    }

    @Override
    public FileIO resolve(File workDir, String pathname, int oflags) {
        return null;
    }
}