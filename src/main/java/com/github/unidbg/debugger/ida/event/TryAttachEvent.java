package com.github.unidbg.debugger.ida.event;

import com.github.unidbg.Emulator;
import com.github.unidbg.debugger.ida.DebuggerEvent;
import com.github.unidbg.debugger.ida.Utils;
import com.github.unidbg.pointer.UnicornPointer;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class TryAttachEvent extends DebuggerEvent {

    @Override
    public byte[] pack(Emulator<?> emulator) {
        ByteBuffer buffer = ByteBuffer.allocate(0x100);
        buffer.put(Utils.pack_dd(0x2));
        buffer.put(Utils.pack_dd(0x1));
        buffer.put(Utils.pack_dd(emulator.getPid()));
        buffer.put(Utils.pack_dd(emulator.getPid()));
        UnicornPointer pc = emulator.getContext().getPCPointer();
        if (emulator.is32Bit()) {
            buffer.put(Utils.pack_dd(pc.toUIntPeer() + 1));
        } else {
            buffer.put(Utils.pack_dd(pc.peer + 1));
        }
        buffer.putShort((short) 1);
        byte[] data = "unidbg".getBytes();
        buffer.put(Arrays.copyOf(data, data.length + 1));
        buffer.put(Utils.pack_dd(1)); // base
        buffer.put((byte) 0);
        buffer.put(Utils.pack_dd(emulator.getPageAlign() + 1));
        buffer.put((byte) 0);
        buffer.put(Utils.pack_dd(1)); // base
        buffer.put((byte) 0);
        return flipBuffer(buffer);
    }

    @Override
    public void onAck(ByteBuffer buffer) {
    }
}
