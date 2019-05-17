package cn.banny.unidbg;

import cn.banny.unidbg.memory.SvcMemory;
import cn.banny.unidbg.pointer.UnicornPointer;

public interface Svc {

    UnicornPointer onRegister(SvcMemory svcMemory, int svcNumber);

    int handle(Emulator emulator);

}
