package cn.banny.unidbg.memory;

import cn.banny.unidbg.Svc;
import cn.banny.unidbg.pointer.UnicornPointer;

public interface SvcMemory {

    UnicornPointer allocate(int size);

    UnicornPointer registerSvc(Svc svc);

    Svc getSvc(int svcNumber);

}
