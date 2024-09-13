package com.github.unidbg.arm;

import com.github.unidbg.Emulator;
import com.github.unidbg.Svc;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public abstract class Arm64Svc implements Svc {

    private static final Logger log = LoggerFactory.getLogger(Arm64Svc.class);

    public static final int SVC_MAX = 0xffff;

    public static int assembleSvc(int svcNumber) {
        if (svcNumber >= 0 && svcNumber < SVC_MAX - 1) {
            return 0xd4000001 | (svcNumber << 5);
        } else {
            throw new IllegalStateException("svcNumber=0x" + Integer.toHexString(svcNumber));
        }
    }

    private final String name;

    public Arm64Svc() {
        this(null);
    }

    public Arm64Svc(String name) {
        this.name = name;
    }

    @Override
    public UnidbgPointer onRegister(SvcMemory svcMemory, int svcNumber) {
        if (log.isDebugEnabled()) {
            log.debug("onRegister: {}", getClass(), new Exception("svcNumber=0x" + Integer.toHexString(svcNumber)));
        }

        String name = getName();
        return register(svcMemory, svcNumber, name == null ? "Arm64Svc" : name);
    }

    private static UnidbgPointer register(SvcMemory svcMemory, int svcNumber, String name) {
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(assembleSvc(svcNumber)); // "svc #0x" + Integer.toHexString(svcNumber)
        buffer.putInt(0xd65f03c0); // ret

        byte[] code = buffer.array();
        UnidbgPointer pointer = svcMemory.allocate(code.length, name);
        pointer.write(0, code, 0, code.length);
        return pointer;
    }

    @Override
    public void handlePostCallback(Emulator<?> emulator) {
    }

    @Override
    public void handlePreCallback(Emulator<?> emulator) {
    }

    @Override
    public String getName() {
        return name;
    }
}
