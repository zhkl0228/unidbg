package com.github.unidbg.debugger.ida;

import com.github.unidbg.Emulator;

import java.nio.ByteBuffer;

public abstract class DebuggerEvent {

    protected final byte[] flipBuffer(ByteBuffer buffer) {
        buffer.flip();
        byte[] data = new byte[buffer.remaining()];
        buffer.get(data);
        return data;
    }

    public abstract byte[] pack(Emulator<?> emulator);

    public abstract void onAck(ByteBuffer buffer);

}
