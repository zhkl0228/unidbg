package cn.banny.emulator.hook;

import cn.banny.emulator.Emulator;
import unicorn.Unicorn;

public interface InterceptCallback {

    void onIntercept(Unicorn u, Emulator emulator);

}
