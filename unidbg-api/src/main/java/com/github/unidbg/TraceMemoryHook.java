package com.github.unidbg;

import com.alibaba.fastjson.util.IOUtils;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.backend.ReadHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.arm.backend.WriteHook;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.listener.TraceReadListener;
import com.github.unidbg.listener.TraceWriteListener;
import com.github.unidbg.pointer.UnidbgPointer;
import org.apache.commons.codec.binary.Hex;

import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * trace memory read
 * Created by zhkl0228 on 2017/5/2.
 */

public class TraceMemoryHook implements ReadHook, WriteHook, TraceHook {

    private final boolean read;
    private final DateFormat dateFormat = new SimpleDateFormat("[HH:mm:ss SSS]");

    public TraceMemoryHook(boolean read) {
        this.read = read;
    }

    private PrintStream redirect;
    TraceReadListener traceReadListener;
    TraceWriteListener traceWriteListener;

    private UnHook unHook;

    @Override
    public void onAttach(UnHook unHook) {
        if (this.unHook != null) {
            throw new IllegalStateException();
        }
        this.unHook = unHook;
    }

    @Override
    public void detach() {
        if (unHook != null) {
            unHook.unhook();
            unHook = null;
        }
    }

    @Override
    public void stopTrace() {
        detach();
        IOUtils.close(redirect);
        redirect = null;
    }

    @Override
    public void setRedirect(PrintStream redirect) {
        this.redirect = redirect;
    }

    @Override
    public void hook(Backend backend, long address, int size, Object user) {
        if (!read) {
            return;
        }

        try {
            byte[] data = size == 0 ? new byte[0] : backend.mem_read(address, size);
            String value;
            if (data.length == 4) {
                value = "0x" + Long.toHexString(ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).getInt() & 0xffffffffL);
            } else if (data.length == 8) {
                value = "0x" + Long.toHexString(ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).getLong());
            } else {
                value = "0x" + Hex.encodeHexString(data);
            }
            Emulator<?> emulator = (Emulator<?>) user;
            if (traceReadListener == null || traceReadListener.onRead(emulator, address, data, value)) {
                printMsg(dateFormat.format(new Date()) + " Memory READ at 0x", emulator, address, size, value);
            }
        } catch (BackendException e) {
            throw new IllegalStateException(e);
        }
    }

    private void printMsg(String type, Emulator<?> emulator, long address, int size, String value) {
        RegisterContext context = emulator.getContext();
        UnidbgPointer pc = context.getPCPointer();
        UnidbgPointer lr = context.getLRPointer();
        PrintStream out = System.out;
        if (redirect != null) {
            out = redirect;
        }
        StringBuilder builder = new StringBuilder();
        builder.append(type).append(Long.toHexString(address));
        if (size > 0) {
            builder.append(", data size = ").append(size).append(", data value = ").append(value);
        }
        builder.append(", PC=").append(pc).append(", LR=").append(lr);
        out.println(builder.toString());
    }

    @Override
    public void hook(Backend backend, long address, int size, long value, Object user) {
        if (read) {
            return;
        }

        try {
            Emulator<?> emulator = (Emulator<?>) user;
            if (traceWriteListener == null || traceWriteListener.onWrite(emulator, address, size, value)) {
                printMsg(dateFormat.format(new Date()) + " Memory WRITE at 0x", emulator, address, size, "0x" + Long.toHexString(value));
            }
        } catch (BackendException e) {
            throw new IllegalStateException(e);
        }
    }

}
