package cn.banny.emulator.linux;

import cn.banny.emulator.Emulator;

public interface ModuleListener {

    void onLoaded(Emulator emulator, Module module);

}
