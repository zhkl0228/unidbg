package cn.banny.emulator.hook;

import cn.banny.emulator.Emulator;
import unicorn.Unicorn;

public interface HookCallback {

    int onHook(Unicorn u, Emulator emulator);

}
