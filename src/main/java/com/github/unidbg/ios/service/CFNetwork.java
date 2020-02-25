package com.github.unidbg.ios.service;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.substrate.ISubstrate;
import com.github.unidbg.ios.Substrate;
import com.github.unidbg.ios.objc.ObjC;
import com.github.unidbg.ios.struct.objc.ObjcClass;
import com.github.unidbg.ios.struct.objc.ObjcObject;
import com.github.unidbg.pointer.UnicornPointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class CFNetwork extends FrameworkHooker {

    private static final Log log = LogFactory.getLog(CFNetwork.class);

    @Override
    protected void doHook(Emulator<?> emulator, Module module) {
        Symbol _CFNetworkCopySystemProxySettings = module.findSymbolByName("_CFNetworkCopySystemProxySettings", false);
        if (_CFNetworkCopySystemProxySettings == null) {
            throw new IllegalStateException("_CFNetworkCopySystemProxySettings is null");
        }

        ObjC objc = ObjC.getInstance(emulator);
        final ObjcClass cNSDictionary = objc.getClass("NSDictionary");
        final ObjcObject fakeProxySettings = cNSDictionary.callObjc("dictionary");

        ISubstrate substrate = Substrate.getInstance(emulator);
        substrate.hookFunction(_CFNetworkCopySystemProxySettings, new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                if (log.isDebugEnabled()) {
                    log.debug("_CFNetworkCopySystemProxySettings");
                }
                UnicornPointer pointer = (UnicornPointer) fakeProxySettings.getPointer();
                return HookStatus.LR(emulator, pointer.peer);
            }
        });
    }

}
