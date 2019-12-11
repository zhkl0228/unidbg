package cn.banny.unidbg;

import cn.banny.unidbg.arm.context.RegisterContext;
import cn.banny.unidbg.listener.TraceReadListener;
import cn.banny.unidbg.listener.TraceWriteListener;
import cn.banny.unidbg.pointer.UnicornPointer;
import cn.banny.utils.Hex;
import unicorn.MemHook;
import unicorn.Unicorn;

import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * trace memory read
 * Created by zhkl0228 on 2017/5/2.
 */

class TraceMemoryHook implements MemHook {

    private final boolean read;

    TraceMemoryHook(boolean read) {
        this.read = read;
    }

    PrintStream redirect;
    TraceReadListener traceReadListener;
    TraceWriteListener traceWriteListener;

    @Override
    public void hook(Unicorn u, long address, int size, Object user) {
        if (!read) {
            return;
        }

        byte[] data = u.mem_read(address, size);
        String value;
        if (data.length == 4) {
            value = "0x" + Long.toHexString(ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).getInt() & 0xffffffffL);
        } else {
            value = Hex.encodeHexString(data);
        }
        Emulator emulator = (Emulator) user;
        if (traceReadListener != null) {
            traceReadListener.onRead(emulator, address, data, value);
        }
        printMsg("### Memory READ at 0x", emulator, address, size, value);
    }

    private void printMsg(String type, Emulator emulator, long address, int size, String value) {
        RegisterContext context = emulator.getContext();
        UnicornPointer pc = context.getPCPointer();
        UnicornPointer lr = context.getLRPointer();
        PrintStream out = System.out;
        if (redirect != null) {
            out = redirect;
        }
        String sb = type + Long.toHexString(address) + ", data size = " + size + ", data value = " + value +
                " pc=" + pc +
                " lr=" + lr;
        out.println(sb);
    }

    @Override
    public void hook(Unicorn u, long address, int size, long value, Object user) {
        if (read) {
            return;
        }

        Emulator emulator = (Emulator) user;
        if (traceWriteListener != null) {
            traceWriteListener.onWrite(emulator, address, size, value);
        }
        printMsg("### Memory WRITE at 0x", emulator, address, size, "0x" + Long.toHexString(value));
    }

}
