package cn.banny.emulator.memory;

import cn.banny.emulator.Svc;
import cn.banny.emulator.pointer.UnicornPointer;

public interface SvcMemory {

    UnicornPointer allocate(int size);

    UnicornPointer registerSvc(Svc svc);

    Svc getSvc(int svcNumber);

}
