package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.hook.HookContext;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.substrate.ISubstrate;
import com.github.unidbg.ios.hook.Substrate;
import com.github.unidbg.ios.ipa.EmulatorConfigurator;
import com.github.unidbg.ios.ipa.IpaLoader;
import com.github.unidbg.ios.ipa.LoadedIpa;
import com.github.unidbg.ios.objc.NSData;
import com.github.unidbg.ios.objc.ObjC;
import com.github.unidbg.ios.struct.objc.ObjcClass;
import com.github.unidbg.ios.struct.objc.ObjcObject;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.unix.UnixEmulator;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import org.apache.commons.codec.binary.Hex;

import java.io.File;
import java.util.concurrent.Callable;

public abstract class WeChatTest implements IOResolver<DarwinFileIO>, EmulatorConfigurator {

    @Override
    public FileResult<DarwinFileIO> resolve(Emulator<DarwinFileIO> emulator, String pathname, int oflags) {
        if ("/private/jailbreak.txt".equals(pathname)) {
            return FileResult.failed(UnixEmulator.EACCES);
        }
        return null;
    }

    @Override
    public void configure(Emulator<DarwinFileIO> emulator, String executableBundlePath, File rootDir, String bundleIdentifier) {
        emulator.getSyscallHandler().addIOResolver(this);
    }

    protected abstract IpaLoader createLoader(File rootDir);

    final void test() throws Exception {
        LoadedIpa loader = createLoader(new File("target/rootfs/wechat")).load(this);

        final Emulator<DarwinFileIO> emulator = loader.getEmulator();

        ISubstrate substrate = Substrate.getInstance(emulator);
        final ObjC objc = ObjC.getInstance(emulator);
        patch(emulator, substrate, objc);

        loader.setCallFinishLaunchingWithOptions(true);
        loader.setIdentifierForVendor("00000000-8888-0000-0000-000000000000");
        loader.setAdvertisingIdentifier("00000000-2222-0000-2222-000000000000");
        loader.setCarrierName("CMCC");
        loader.callEntry();
        init(emulator);

        ObjcClass cMMServiceCenter = objc.getClass("MMServiceCenter");
        final ObjcObject serviceCenter = getMMServiceCenter(objc, cMMServiceCenter);

        ObjcClass cFPInitResponse = objc.lookUpClass("FPInitResponse");
        if(cFPInitResponse != null) {
            ObjcClass cNSData = objc.getClass("NSData");
            byte[] bytes = Hex.decodeHex("0a06080012020a0012aa0412be020a8001693f613b673f386b6f3767356230346408555455040659580d0f510a06565805035206045055080631653e306c3033635a560206540655576135346132393433383832376130396163613630643561343737343461663831633564393262653806070006535051513c3a603c323d6b683436653e6764626806040f545d02520212b80144594501060000000e307185c4eeffff3001096c30030a450e070b8130040acf30050f970e070c830e070ed70e030d6a0e020c620e030bb60e010d6030060d230e040fcb30070ac230000b2a3006094f300109250e0308d20e030b76300308e1300409730e060cfc0e020fbd300009f630060dcb30010df030060ae630030be430070a0f30010d130e020f110e0609f530070e7b0e050d5030050ca330010baa0e020edf30030d8430030edd30020c430e0308e9eeb386001ae00130303064323233643365303430303030303130303030303030303030643731626130636536323034353362313931333530343564356635653230303030303030666338653634326362356234393164386130356135303034643439636638623935326331623831396462316464306666303039623032303338613664326163383935653932323531396137393134633731386135373162343934633731306463326464353733333333356238373666656232633738313837336564386133356431386433646538306263363432373233393563613033393736393437366465352084a38df305".toCharArray());
            ObjcObject data = cNSData.callObjc("dataWithBytes:length:", bytes, bytes.length);
            ObjcObject response = cFPInitResponse.callObjc("parseFromData:", data);

            ObjcClass cProtobufCGIWrap = objc.getClass("ProtobufCGIWrap");
            ObjcObject wrap = cProtobufCGIWrap.callObjc("new");
            wrap.callObjc("setM_uiCgi:", 0xe3c); // fpInit
            wrap.callObjc("setM_pbResponse:", response);

            ObjcClass cFPManager = objc.getClass("FPManager");
            ObjcObject fpManager = serviceCenter.callObjc("getService:", cFPManager);
            fpManager.callObjc("updateResponse:Event:", wrap, 0);
        }

        doMore(emulator);

        Callable<Void> callable = new Callable<Void>() {
            @Override
            public Void call() {
                long start = System.currentTimeMillis();
                ObjcClass cMMClientCacheManager = objc.getClass("MMClientCacheManager");
                ObjcObject clientCacheManager = serviceCenter.callObjc("getService:", cMMClientCacheManager);
                ObjcObject basicData = clientCacheManager.callObjc("getBasicData");
                NSData data = basicData.toNSData();
                Inspector.inspect(data.getBytes(), "offset=" + (System.currentTimeMillis() - start) + "ms");
                return null;
            }
        };
        emulator.attach().run(callable);
    }

    protected ObjcObject getMMServiceCenter(ObjC objc, ObjcClass cMMServiceCenter) {
        return cMMServiceCenter.callObjc("defaultCenter");
    }

    protected void doMore(Emulator<DarwinFileIO> emulator) {}

    void init(Emulator<?> emulator) {
        Memory memory = emulator.getMemory();

        final int kLevelAll = 0;
        Module mars = memory.findModule("mars");
        Symbol appender_set_console_log = mars.findSymbolByName("__Z24appender_set_console_logb", false);
        Symbol xlogger_SetLevel = mars.findSymbolByName("_xlogger_SetLevel", false);
        if (appender_set_console_log != null) {
            appender_set_console_log.call(emulator, 1);
            System.out.println("Call appender_set_console_log finished");
        }
        xlogger_SetLevel.call(emulator, kLevelAll);
        System.out.println("Call xlogger_SetLevel finished");

        Symbol __xlogger_Assert_impl = mars.findSymbolByName("___xlogger_Assert_impl", false);
        ISubstrate substrate = Substrate.getInstance(emulator);
        substrate.hookFunction(__xlogger_Assert_impl, new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                Pointer info = context.getPointerArg(0);
                Pointer pointer = context.getPointerArg(2);
                if (info != null && pointer != null) {
                    Pointer tag = info.getPointer(emulator.getPointerSize());
                    Pointer filename = info.getPointer(emulator.getPointerSize() * 2);
                    Pointer func_name = info.getPointer(emulator.getPointerSize() * 3);
                    int line = info.getInt(emulator.getPointerSize() * 4);
                    String sb = "__xloggerA[" + tag.getString(0) + "]" +
                            filename.getString(0) + "->" + func_name.getString(0) +
                            "@" + line + ": " +
                            pointer.getString(0);
                    System.err.println(sb);
                }
                return super.onCall(emulator, context, originFunction);
            }
        });
    }

    protected void patch(Emulator<DarwinFileIO> emulator, ISubstrate substrate, ObjC objc) {
        ObjcClass cMMOOMCrashReport = objc.getClass("MMOOMCrashReport");
        substrate.hookMessageEx(cMMOOMCrashReport.getMeta(), objc.registerName("checkRebootType"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                System.out.println("Patch [MMOOMCrashReport checkRebootType]");
                return HookStatus.LR(emulator, 0);
            }
        });

        ObjcClass cMemoryStatManager = objc.getClass("MemoryStatManager");
        substrate.hookMessageEx(cMemoryStatManager.getMeta(), objc.registerName("sharedInstance"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                System.out.println("Patch [MemoryStatManager sharedInstance]");
                return HookStatus.LR(emulator, 0);
            }
        });

        ObjcClass cWCMatrixManager = objc.getClass("WCMatrixManager");
        substrate.hookMessageEx(cWCMatrixManager.getMeta(), objc.registerName("sharedInstance"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                System.out.println("Patch [WCMatrixManager sharedInstance]");
                return HookStatus.LR(emulator, 0);
            }
        });

        ObjcClass cWCCrashBlockExtensionHandler = objc.getClass("WCCrashBlockExtensionHandler");
        substrate.hookMessageEx(cWCCrashBlockExtensionHandler.getMeta(), objc.registerName("shareInstance"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                System.out.println("Patch [WCCrashBlockExtensionHandler shareInstance]");
                return HookStatus.LR(emulator, 0);
            }
        });

        ObjcClass cMMWatchDogMonitor = objc.getClass("MMWatchDogMonitor");
        substrate.hookMessageEx(cMMWatchDogMonitor.getMeta(), objc.registerName("beginMonitor"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                System.out.println("Patch [MMWatchDogMonitor beginMonitor]");
                return HookStatus.LR(emulator, 0);
            }
        });

        ObjcClass cMicroMessengerAppDelegate = objc.getClass("MicroMessengerAppDelegate");
        substrate.hookMessageEx(cMicroMessengerAppDelegate, objc.registerName("mainUISetting"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                System.out.println("Patch [MicroMessengerAppDelegate mainUISetting]");
                return HookStatus.LR(emulator, 0);
            }
        });
        substrate.hookMessageEx(cMicroMessengerAppDelegate, objc.registerName("shouldEnterSafeMode"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                System.out.println("Patch [MicroMessengerAppDelegate shouldEnterSafeMode]");
                return HookStatus.LR(emulator, 0);
            }
        });
        substrate.hookMessageEx(cMicroMessengerAppDelegate, objc.registerName("beforeMainLaunching"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                System.out.println("Patch [MicroMessengerAppDelegate beforeMainLaunching]");
                return HookStatus.LR(emulator, 0);
            }
        });
        substrate.hookMessageEx(cMicroMessengerAppDelegate, objc.registerName("continueMainLaunching:"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                System.out.println("Patch [MicroMessengerAppDelegate continueMainLaunching]");
                return HookStatus.LR(emulator, 0);
            }
        });
    }

}
