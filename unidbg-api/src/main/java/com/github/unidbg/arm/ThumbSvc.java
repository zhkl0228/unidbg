package com.github.unidbg.arm;

import com.github.unidbg.Emulator;
import com.github.unidbg.Svc;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public abstract class ThumbSvc implements Svc {

    public static final int SVC_MAX = 0xff;

    public static short assembleSvc(int svcNumber) {
        if (svcNumber >= 0 && svcNumber < SVC_MAX - 1) {
            return (short) (0xdf00 | svcNumber);
        } else {
            throw new IllegalStateException("svcNumber=0x" + Integer.toHexString(svcNumber));
        }
    }

    private final String name;

    public ThumbSvc() {
        this(null);
    }

    public ThumbSvc(String name) {
        this.name = name;
    }

    @Override
    public UnidbgPointer onRegister(SvcMemory svcMemory, int svcNumber) {
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putShort(assembleSvc(svcNumber)); // svc #svcNumber
        buffer.putShort((short) 0x4770); // bx lr
        byte[] code = buffer.array();
        String name = getName();
        UnidbgPointer pointer = svcMemory.allocate(code.length, name == null ? "ThumbSvc" : name);
        pointer.write(code);
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
