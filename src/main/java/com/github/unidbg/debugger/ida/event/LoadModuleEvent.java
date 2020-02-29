package com.github.unidbg.debugger.ida.event;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.debugger.ida.DebuggerEvent;
import com.github.unidbg.debugger.ida.Utils;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class LoadModuleEvent extends DebuggerEvent {

    private final Module module;

    public LoadModuleEvent(Module module) {
        this.module = module;
    }

    @Override
    public byte[] pack(Emulator<?> emulator) {
        ByteBuffer buffer = ByteBuffer.allocate(0x100);
        buffer.put(Utils.pack_dd(0x2));
        buffer.put(Utils.pack_dd(0x80));
        buffer.put(Utils.pack_dd(emulator.getPid()));
        buffer.put(Utils.pack_dd(emulator.getPid()));
        buffer.put(Utils.pack_dd(module.base + 1));
        buffer.putShort((short) 1);
        byte[] data = module.getPath().getBytes();
        buffer.put(Arrays.copyOf(data, data.length + 1));
        buffer.put(Utils.pack_dd(module.base + 1));
        buffer.put((byte) 0);
        buffer.put(Utils.pack_dd(module.size + 1));
        buffer.put((byte) 0);
        buffer.put(Utils.pack_dd(0));
        buffer.put((byte) 1);
        return Utils.flipBuffer(buffer);
    }

}
