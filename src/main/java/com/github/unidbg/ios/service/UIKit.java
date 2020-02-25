package com.github.unidbg.ios.service;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.substrate.ISubstrate;
import com.github.unidbg.ios.Substrate;
import com.github.unidbg.ios.objc.ObjC;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class UIKit extends FrameworkHooker {

    private static final Log log = LogFactory.getLog(UIKit.class);

    @Override
    protected void doHook(Emulator<?> emulator, Module module) {
        ObjC objc = ObjC.getInstance(emulator);
        ISubstrate substrate = Substrate.getInstance(emulator);
        substrate.hookMessageEx(objc.getClass("UIDevice"), objc.registerName("setBatteryMonitoringEnabled:"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                RegisterContext context = emulator.getContext();
                int status = context.getIntArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("UIDevice setBatteryMonitoringEnabled status=" + status);
                }
                return HookStatus.LR(emulator, 0);
            }
        });
    }

}
