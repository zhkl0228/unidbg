package com.github.unidbg.debugger.ida.event;

import com.github.unidbg.Emulator;
import com.github.unidbg.debugger.DebugServer;
import com.github.unidbg.debugger.ida.DebuggerEvent;
import com.github.unidbg.debugger.ida.Utils;
import com.github.unidbg.pointer.UnidbgPointer;

import java.nio.ByteBuffer;

public class AttachExecutableEvent extends DebuggerEvent {

    @Override
    public byte[] pack(Emulator<?> emulator) {
        ByteBuffer buffer = ByteBuffer.allocate(0x100);
        buffer.put(Utils.pack_dd(0x1));
        buffer.put(Utils.pack_dd(0x400));
        buffer.put(Utils.pack_dd(emulator.getPid()));
        buffer.put(Utils.pack_dd(emulator.getPid()));
        UnidbgPointer pc = emulator.getContext().getPCPointer();
        if (emulator.is32Bit()) {
            buffer.put(Utils.pack_dq(pc.toUIntPeer() + 1));
        } else {
            buffer.put(Utils.pack_dq(pc.peer + 1));
        }
        buffer.put((byte) 1);
        Utils.writeCString(buffer, DebugServer.DEBUG_EXEC_NAME);
        buffer.put(Utils.pack_dq(1)); // base
        buffer.put(Utils.pack_dq(emulator.getPageAlign() + 1));
        buffer.put(Utils.pack_dq(1)); // base
        return Utils.flipBuffer(buffer);
    }
}
