package com.github.unidbg.arm;

import com.github.unidbg.Emulator;
import com.github.unidbg.Svc;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public abstract class ArmSvc implements Svc {

    public static int assembleSvc(int svcNumber) {
        return 0xef000000 | svcNumber;
    }

    @Override
    public UnidbgPointer onRegister(SvcMemory svcMemory, int svcNumber) {
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(assembleSvc(svcNumber)); // svc #svcNumber
        buffer.putInt(0xe12fff1e); // bx lr
        byte[] code = buffer.array();
        UnidbgPointer pointer = svcMemory.allocate(code.length, "ArmSvc");
        pointer.write(code);
        return pointer;
    }

    @Override
    public void handleCallback(Emulator<?> emulator) {
    }

}
