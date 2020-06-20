package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.hook.HookContext;
import com.github.unidbg.hook.HookLoader;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.fishhook.IFishHook;
import com.github.unidbg.hook.substrate.ISubstrate;
import com.github.unidbg.ios.hook.FishHook;
import com.github.unidbg.ios.ipa.IpaLoader;
import com.github.unidbg.ios.ipa.IpaLoader64;
import com.github.unidbg.ios.objc.ObjC;
import com.github.unidbg.ios.struct.objc.ObjcClass;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;

import java.io.File;

public class WeChat7012Test extends WeChatTest {

    public static void main(String[] args) throws Exception {
        new WeChat7012Test().test();
    }

    @Override
    protected IpaLoader createLoader(File rootDir) {
        return new IpaLoader64(new File("target/com.tencent.xin_7.0.12.ipa"), rootDir);
    }

    @Override
    void init(Emulator<?> emulator) {
        super.init(emulator);

        IFishHook fishHook = FishHook.getInstance(emulator);
        Module module = emulator.getMemory().findModule("WeChat");
        fishHook.rebindSymbolImage(module, "strlen", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                Pointer str = context.getPointerArg(0);
                System.out.println("srlen str=" + str.getString(0) + ", LR=" + context.getLRPointer());
                return super.onCall(emulator, context, originFunction);
            }
        });
        fishHook.rebindSymbolImage(module, "memcpy", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                Pointer dest = context.getPointerArg(0);
                Pointer src = context.getPointerArg(1);
                int size = context.getIntArg(2);
                if (size > 0x50) {
                    size = 0x50;
                }
                Inspector.inspect(src.getByteArray(0, size), "memcpy src=" + src + ", dest=" + dest);
                return super.onCall(emulator, context, originFunction);
            }
        });

        HookLoader.load(emulator).hookObjcMsgSend(null);
    }

    @Override
    protected void patch(Emulator<DarwinFileIO> emulator, ISubstrate substrate, ObjC objc) {
        super.patch(emulator, substrate, objc);

        ObjcClass cWCSDKAdapter = objc.getClass("WCSDKAdapter");
        substrate.hookMessageEx(cWCSDKAdapter.getMeta(), objc.registerName("setup"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                System.out.println("Patch [WCSDKAdapter setup]");
                return HookStatus.LR(emulator, 0);
            }
        });

        ObjcClass cWAAdapterMgr = objc.getClass("WAAdapterMgr");
        substrate.hookMessageEx(cWAAdapterMgr.getMeta(), objc.registerName("setup"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                System.out.println("Patch [WAAdapterMgr setup]");
                return HookStatus.LR(emulator, 0);
            }
        });
    }

}
