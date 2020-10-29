package com.github.unidbg.arm;

import com.github.unidbg.Emulator;
import com.github.unidbg.Svc;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public abstract class ThumbSvc implements Svc {

    public static short assembleSvc(int svcNumber) {
        if (svcNumber > 0 && svcNumber <= 0xff) {
            return (short) (0xdf00 | svcNumber);
        } else {
            throw new IllegalStateException("svcNumber=0x" + Integer.toHexString(svcNumber));
        }
    }

    @Override
    public UnidbgPointer onRegister(SvcMemory svcMemory, int svcNumber) {
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putShort(assembleSvc(svcNumber)); // svc #svcNumber
        buffer.putShort((short) 0x4770); // bx lr
        byte[] code = buffer.array();
        UnidbgPointer pointer = svcMemory.allocate(code.length, "ThumbSvc");
        pointer.write(code);
        return pointer;
    }

    @Override
    public void handleCallback(Emulator<?> emulator) {
    }

}
