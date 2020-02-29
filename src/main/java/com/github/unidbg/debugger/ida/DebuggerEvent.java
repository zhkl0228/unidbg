package com.github.unidbg.debugger.ida;

import com.github.unidbg.Emulator;

import java.nio.ByteBuffer;

public abstract class DebuggerEvent {

    public abstract byte[] pack(Emulator<?> emulator);

    public abstract void onAck(ByteBuffer buffer);

}
