package com.github.unidbg.debugger.ida.event;

import com.github.unidbg.Emulator;
import com.github.unidbg.debugger.ida.DebuggerEvent;
import com.github.unidbg.debugger.ida.Utils;

import java.nio.ByteBuffer;

public class DetachEvent extends DebuggerEvent {

    @Override
    public byte[] pack(Emulator<?> emulator) {
        ByteBuffer buffer = ByteBuffer.allocate(0x20);
        buffer.put(Utils.pack_dd(0x1));
        buffer.put(Utils.pack_dd(0x800));
        buffer.put(Utils.pack_dd(emulator.getPid()));
        buffer.put(Utils.pack_dd(emulator.getPid()));
        buffer.put(Utils.pack_dq(0x100000000L));
        buffer.put((byte) 1);
        return Utils.flipBuffer(buffer);
    }
}
