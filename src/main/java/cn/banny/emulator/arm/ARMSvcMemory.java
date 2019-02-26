package cn.banny.emulator.arm;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.Svc;
import cn.banny.emulator.memory.SvcMemory;
import cn.banny.emulator.pointer.UnicornPointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Unicorn;
import unicorn.UnicornConst;

import java.util.HashMap;
import java.util.Map;

public class ARMSvcMemory implements SvcMemory {

    private static final Log log = LogFactory.getLog(SvcMemory.class);

    private UnicornPointer base;

    ARMSvcMemory(Unicorn unicorn, long base, int size, Emulator emulator) {
        this.base = UnicornPointer.pointer(emulator, base);
        assert this.base != null;
        this.base.setSize(size);

        unicorn.mem_map(base, size, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_EXEC);
    }

    @Override
    public UnicornPointer allocate(int size) {
        size = ARM.alignSize(size);
        UnicornPointer pointer = base.share(0, size);
        base = (UnicornPointer) base.share(size);
        return pointer;
    }

    private int thumbSvcNumber = 0;
    private int armSvcNumber = 0xff;

    private final Map<Integer, Svc> svcMap = new HashMap<>();

    @Override
    public Svc getSvc(int svcNumber) {
        return svcMap.get(svcNumber);
    }

    @Override
    public UnicornPointer registerSvc(Svc svc) {
        final int number;
        if (svc instanceof ThumbSvc) {
            number = ++thumbSvcNumber;
        } else if (svc instanceof ArmSvc || svc instanceof Arm64Svc) {
            number = ++armSvcNumber;
        } else {
            throw new IllegalStateException();
        }
        if (svcMap.put(number, svc) != null) {
            throw new IllegalStateException();
        }
        return svc.onRegister(this, number);
    }

}
