package com.github.unidbg.debugger.ida.event;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.debugger.ida.DebuggerEvent;
import com.github.unidbg.debugger.ida.Utils;

import java.nio.ByteBuffer;

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
        buffer.put(Utils.pack_dq(module.base + 1));
        buffer.put(Utils.pack_dd(0x1));
        Utils.writeCString(buffer, module.getPath());
        buffer.put(Utils.pack_dq(module.base + 1));
        buffer.put(Utils.pack_dq(module.size + 1));
        buffer.put(Utils.pack_dq(0x0));
        return Utils.flipBuffer(buffer);
    }

}
