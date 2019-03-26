package cn.banny.emulator;

import cn.banny.emulator.memory.SvcMemory;
import cn.banny.emulator.pointer.UnicornPointer;

public interface Svc {

    UnicornPointer onRegister(SvcMemory svcMemory, int svcNumber);

    int handle(Emulator emulator);

}
