package com.github.unidbg.ios.service;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.substrate.ISubstrate;
import com.github.unidbg.ios.hook.Substrate;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class Security extends FrameworkHooker {

    private static final Log log = LogFactory.getLog(Security.class);

    private static final int errSecSuccess                            = 0; /* No error. */
    private static final int errSecItemNotFound                       = -25300; /* The specified item could not be found in the keychain. */

    @Override
    protected void doHook(Emulator<?> emulator, Module module) {
        Symbol _SecItemCopyMatching = module.findSymbolByName("_SecItemCopyMatching", false);
        if (_SecItemCopyMatching == null) {
            throw new IllegalStateException("_SecItemCopyMatching is null");
        }
        Symbol _SecItemDelete = module.findSymbolByName("_SecItemDelete", false);
        if (_SecItemDelete == null) {
            throw new IllegalStateException("_SecItemDelete is null");
        }
        Symbol _SecItemAdd = module.findSymbolByName("_SecItemAdd", false);
        if (_SecItemAdd == null) {
            throw new IllegalStateException("_SecItemAdd is null");
        }

        ISubstrate substrate = Substrate.getInstance(emulator);
        substrate.hookFunction(_SecItemCopyMatching, new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                RegisterContext context = emulator.getContext();
                Pointer query = context.getPointerArg(0);
                Pointer result = context.getPointerArg(1);
                if (log.isDebugEnabled()) {
                    log.debug("_SecItemCopyMatching query=" + query + ", result=" + result);
                }
                return HookStatus.LR(emulator, errSecItemNotFound);
            }
        });
        substrate.hookFunction(_SecItemDelete, new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                RegisterContext context = emulator.getContext();
                Pointer query = context.getPointerArg(0);
                if (log.isDebugEnabled()) {
                    log.debug("_SecItemDelete query=" + query);
                }
                return HookStatus.LR(emulator, errSecSuccess);
            }
        });
        substrate.hookFunction(_SecItemAdd, new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                RegisterContext context = emulator.getContext();
                Pointer attributes = context.getPointerArg(0);
                Pointer result = context.getPointerArg(1);
                if (log.isDebugEnabled()) {
                    log.debug("_SecItemAdd attributes=" + attributes + ", result=" + result);
                }
                return HookStatus.LR(emulator, errSecSuccess);
            }
        });
    }

}
