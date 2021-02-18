package com.github.unidbg.arm;

import com.github.unidbg.Emulator;
import com.github.unidbg.Svc;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public abstract class Arm64Svc implements Svc {

    private static final Log log = LogFactory.getLog(Arm64Svc.class);

    public static int assembleSvc(int svcNumber) {
        return 0xd4000001 | (svcNumber << 5);
    }

    @Override
    public UnidbgPointer onRegister(SvcMemory svcMemory, int svcNumber) {
        if (log.isDebugEnabled()) {
            log.debug("onRegister: " + getClass(), new Exception("svcNumber=0x" + Integer.toHexString(svcNumber)));
        }

        return register(svcMemory, svcNumber);
    }

    private static UnidbgPointer register(SvcMemory svcMemory, int svcNumber) {
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(assembleSvc(svcNumber)); // "svc #0x" + Integer.toHexString(svcNumber)
        buffer.putInt(0xd65f03c0); // ret

        byte[] code = buffer.array();
        UnidbgPointer pointer = svcMemory.allocate(code.length, "Arm64Svc");
        pointer.write(0, code, 0, code.length);
        return pointer;
    }

    @Override
    public void handleCallback(Emulator<?> emulator) {
    }

}
