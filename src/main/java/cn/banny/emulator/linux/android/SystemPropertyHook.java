package cn.banny.emulator.linux.android;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.memory.SvcMemory;
import cn.banny.emulator.hook.HookListener;
import cn.banny.emulator.pointer.UnicornPointer;
import cn.banny.emulator.arm.ArmHook;
import cn.banny.emulator.arm.HookStatus;
import com.sun.jna.Pointer;
import unicorn.ArmConst;
import unicorn.Unicorn;
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
                protected HookStatus hook(Unicorn u, Emulator emulator) {
                    if (propertyProvider != null) {
                        Pointer pointer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                        String key = pointer.getString(0);
                        String value = propertyProvider.getProperty(key);
                        if (value != null) {
                            byte[] data = value.getBytes(StandardCharsets.UTF_8);
                            if (data.length >= PROP_VALUE_MAX) {
                                throw new UnicornException("invalid property value length: key=" + key + ", value=" + value);
                            }

                            UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).write(0, Arrays.copyOf(data, data.length + 1), 0, data.length + 1);
                            return HookStatus.LR(u, value.length());
                        }
                    }

                    return HookStatus.RET(u, old);
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
