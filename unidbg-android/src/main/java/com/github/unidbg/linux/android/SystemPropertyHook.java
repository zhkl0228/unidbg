package com.github.unidbg.linux.android;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.Arm64Hook;
import com.github.unidbg.arm.ArmHook;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.context.EditableArm64RegisterContext;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.hook.HookListener;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class SystemPropertyHook implements HookListener {

    private static final Logger log = LoggerFactory.getLogger(SystemPropertyHook.class);

    public static final int PROP_VALUE_MAX = 92;

    private final Emulator<?> emulator;

    public SystemPropertyHook(Emulator<?> emulator) {
        this.emulator = emulator;
    }

    @Override
    public long hook(SvcMemory svcMemory, String libraryName, String symbolName, final long old) {
        if ("libc.so".equals(libraryName)) {
            if ("__system_property_get".equals(symbolName)) {
                log.debug("Hook {}", symbolName);
                if (emulator.is64Bit()) {
                    return svcMemory.registerSvc(new Arm64Hook() {
                        @Override
                        protected HookStatus hook(Emulator<?> emulator) {
                            RegisterContext context = emulator.getContext();
                            int index = 0;
                            Pointer pointer = context.getPointerArg(index);
                            String key = pointer.getString(0);
                            return __system_property_get(old, key, index);
                        }
                    }).peer;
                } else {
                    return svcMemory.registerSvc(new ArmHook() {
                        @Override
                        protected HookStatus hook(Emulator<?> emulator) {
                            RegisterContext context = emulator.getContext();
                            int index = 0;
                            Pointer pointer = context.getPointerArg(index);
                            String key = pointer.getString(0);
                            return __system_property_get(old, key, index);
                        }
                    }).peer;
                }
            }
            if ("__system_property_read".equals(symbolName)) {
                log.debug("Hook {}", symbolName);
                if (emulator.is64Bit()) {
                    return svcMemory.registerSvc(new Arm64Hook() {
                        @Override
                        protected HookStatus hook(Emulator<?> emulator) {
                            RegisterContext context = emulator.getContext();
                            Pointer pi = context.getPointerArg(0);
                            String key = pi.share(PROP_VALUE_MAX + 4).getString(0);
                            return __system_property_get(old, key, 1);
                        }
                    }).peer;
                } else {
                    return svcMemory.registerSvc(new ArmHook() {
                        @Override
                        protected HookStatus hook(Emulator<?> emulator) {
                            RegisterContext context = emulator.getContext();
                            Pointer pi = context.getPointerArg(0);
                            String key = pi.share(PROP_VALUE_MAX + 4).getString(0);
                            return __system_property_get(old, key, 1);
                        }
                    }).peer;
                }
            }
            if ("__system_property_find".equals(symbolName)) {
                log.debug("Hook {}", symbolName);
                if (emulator.is64Bit()) {
                    return svcMemory.registerSvc(new Arm64Hook(true) {
                        private String name;
                        @Override
                        protected HookStatus hook(Emulator<?> emulator) {
                            RegisterContext context = emulator.getContext();
                            Pointer name = context.getPointerArg(0);
                            this.name = name.getString(0);
                            if (log.isDebugEnabled()) {
                                log.debug("__system_property_find key={}, LR={}", this.name, context.getLRPointer());
                            }
                            if (log.isTraceEnabled()) {
                                emulator.attach().debug();
                            }
                            return HookStatus.RET(emulator, old);
                        }
                        @Override
                        public void handlePostCallback(Emulator<?> emulator) {
                            super.handlePostCallback(emulator);
                            EditableArm64RegisterContext context = emulator.getContext();
                            Pointer pi = context.getPointerArg(0);
                            if (log.isDebugEnabled()) {
                                log.debug("__system_property_find key={}, pi={}, value={}", this.name, pi, pi == null ? null : pi.share(4).getString(0));
                            }
                            if (propertyProvider != null) {
                                Pointer replace = propertyProvider.__system_property_find(this.name);
                                if (replace != null) {
                                    context.setXLong(0, UnidbgPointer.nativeValue(replace));
                                }
                            }
                        }
                    }).peer;
                } else {
                    return svcMemory.registerSvc(new ArmHook() {
                        @Override
                        protected HookStatus hook(Emulator<?> emulator) {
                            RegisterContext context = emulator.getContext();
                            Pointer name = context.getPointerArg(0);
                            if (log.isDebugEnabled()) {
                                log.debug("__system_property_find key={}, LR={}", name.getString(0), context.getLRPointer());
                            }
                            if (log.isTraceEnabled()) {
                                emulator.attach().debug();
                            }
                            return HookStatus.RET(emulator, old);
                        }
                    }).peer;
                }
            }
        }
        return 0;
    }

    private HookStatus __system_property_get(long old, String key, int index) {
        RegisterContext context = emulator.getContext();
        if (propertyProvider != null) {
            String value = propertyProvider.getProperty(key);
            if (value != null) {
                log.debug("__system_property_get key={}, value={}", key, value);

                byte[] data = value.getBytes(StandardCharsets.UTF_8);
                if (data.length >= PROP_VALUE_MAX) {
                    throw new BackendException("invalid property value length: key=" + key + ", value=" + value);
                }

                byte[] newData = Arrays.copyOf(data, data.length + 1);
                Pointer pointer = context.getPointerArg(index + 1);
                pointer.write(0, newData, 0, newData.length);
                return HookStatus.LR(emulator, data.length);
            }
        }

        log.debug("__system_property_get key={}", key);
        return HookStatus.RET(emulator, old);
    }

    private SystemPropertyProvider propertyProvider;

    public void setPropertyProvider(SystemPropertyProvider propertyProvider) {
        this.propertyProvider = propertyProvider;
    }

}
