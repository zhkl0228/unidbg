package com.github.unidbg.debugger.ida.event;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.debugger.ida.DebuggerEvent;
import com.github.unidbg.debugger.ida.Utils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class LoadModuleEvent extends DebuggerEvent {

    private static final Log log = LogFactory.getLog(LoadModuleEvent.class);

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
        return flipBuffer(buffer);
    }

    @Override
    public void onAck(ByteBuffer buffer) {
        long type = Utils.unpack_dd(buffer);
        long pid = Utils.unpack_dd(buffer);
        long tid = Utils.unpack_dd(buffer);
        long address = Utils.unpack_dd(buffer);
        short s1 = buffer.getShort();
        String path = Utils.readCString(buffer);
        long base = Utils.unpack_dd(buffer);
        byte b1 = buffer.get();
        long size = Utils.unpack_dd(buffer);
        long b2 = Utils.unpack_dd(buffer);
        long a1 = Utils.unpack_dd(buffer);
        long b3 = Utils.unpack_dd(buffer);
        if (log.isDebugEnabled()) {
            log.debug("onAck type=0x" + Long.toHexString(type) + ", pid=" + pid + ", tid=" + tid +
                    ", address=0x" + Long.toHexString(address) + ", s1=" + s1 + ", path=" + path +
                    ", base=0x" + Long.toHexString(base) + ", b1=" + b1 + ", size=0x" + Long.toHexString(size) +
                    ", b2=" + b2 + ", a1=0x" + Long.toHexString(a1) + ", b3=" + b3);
        }
    }

}
