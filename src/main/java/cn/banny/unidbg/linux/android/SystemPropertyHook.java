package cn.banny.unidbg.linux.android;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.arm.ArmHook;
import cn.banny.unidbg.arm.HookStatus;
import cn.banny.unidbg.arm.context.EditableArm32RegisterContext;
import cn.banny.unidbg.hook.HookListener;
import cn.banny.unidbg.memory.SvcMemory;
import com.sun.jna.Pointer;
import unicorn.UnicornException;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class SystemPropertyHook implements HookListener {

    private static final int PROP_VALUE_MAX = 92;

    @Override
    public long hook(SvcMemory svcMemory, String libraryName, String symbolName, final long old) {
        if ("libc.so".equals(libraryName) && "__system_property_get".equals(symbolName)) {
            return svcMemory.registerSvc(new ArmHook() {
                @Override
                protected HookStatus hook(Emulator emulator) {
                    if (propertyProvider != null) {
                        EditableArm32RegisterContext context = emulator.getContext();
                        Pointer pointer = context.getPointerArg(0);
                        String key = pointer.getString(0);
                        String value = propertyProvider.getProperty(key);
                        if (value != null) {
                            byte[] data = value.getBytes(StandardCharsets.UTF_8);
                            if (data.length >= PROP_VALUE_MAX) {
                                throw new UnicornException("invalid property value length: key=" + key + ", value=" + value);
                            }

                            context.getPointerArg(1).write(0, Arrays.copyOf(data, data.length + 1), 0, data.length + 1);
                            return HookStatus.LR(emulator, value.length());
                        }
                    }

                    return HookStatus.RET(emulator, old);
                }
            }).peer;
        }
        return 0;
    }

    private SystemPropertyProvider propertyProvider;

    public void setPropertyProvider(SystemPropertyProvider propertyProvider) {
        this.propertyProvider = propertyProvider;
    }

}
