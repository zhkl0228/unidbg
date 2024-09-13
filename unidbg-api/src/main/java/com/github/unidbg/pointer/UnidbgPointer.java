package com.github.unidbg.pointer;

import com.github.unidbg.Emulator;
import com.github.unidbg.InvalidMemoryAccessException;
import com.github.unidbg.Module;
import com.github.unidbg.PointerArg;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryMap;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.WString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import unicorn.UnicornConst;

import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class UnidbgPointer extends Pointer implements PointerArg {

    private static final Logger log = LoggerFactory.getLogger(UnidbgPointer.class);

    private final Emulator<?> emulator;
    private final Backend backend;
    public final long peer;
    private final int pointerSize;

    public static long nativeValue(Pointer ptr) {
        if (ptr == null) {
            return 0L;
        }
        UnidbgPointer up = (UnidbgPointer) ptr;
        return up.emulator.is64Bit() ? up.peer : up.toUIntPeer();
    }

    public long toUIntPeer() {
        return peer & 0xffffffffL;
    }

    public int toIntPeer() {
        return (int) toUIntPeer();
    }

    private final MemoryWriteListener listener;

    UnidbgPointer(Emulator<?> emulator, byte[] data) {
        super(0);

        this.emulator = emulator;
        this.backend = data == null ? null : new ByteArrayBackend(data);
        this.peer = 0L;
        this.pointerSize = 0;
        this.listener = null;
    }

    private UnidbgPointer(Emulator<?> emulator, long peer, int pointerSize) {
        super(0);

        this.emulator = emulator;
        this.backend = emulator.getBackend();
        this.peer = peer;
        this.pointerSize = pointerSize;

        if (emulator instanceof MemoryWriteListener) {
            listener = (MemoryWriteListener) emulator;
        } else {
            listener = null;
        }
    }

    private long size;

    public UnidbgPointer setSize(long size) {
        if (size < 0) {
            throw new IllegalArgumentException("size=" + size);
        }
        this.size = size;
        return this;
    }

    public long getSize() {
        return size;
    }

    public static UnidbgPointer pointer(Emulator<?> emulator, long addr) {
        long peer = emulator.is64Bit() ? addr : addr & 0xffffffffL;
        return peer == 0 ? null : new UnidbgPointer(emulator, peer, emulator.getPointerSize());
    }

    public static UnidbgPointer pointer(Emulator<?> emulator, Number number) {
        return pointer(emulator, number.longValue());
    }

    public static UnidbgPointer register(Emulator<?> emulator, int reg) {
        return pointer(emulator, emulator.getBackend().reg_read(reg));
    }

    @Override
    public long indexOf(long offset, byte value) {
        throw new AbstractMethodError();
    }

    @Override
    public void read(long offset, byte[] buf, int index, int length) {
        byte[] data = getByteArray(offset, length);
        System.arraycopy(data, 0, buf, index, length);
    }

    @Override
    public void read(long offset, short[] buf, int index, int length) {
        throw new AbstractMethodError();
    }

    @Override
    public void read(long offset, char[] buf, int index, int length) {
        throw new AbstractMethodError();
    }

    @Override
    public void read(long offset, int[] buf, int index, int length) {
        for (int i = index; i < length; i++) {
            buf[i] = getInt((i - index) * 4L + offset);
        }
    }

    @Override
    public void read(long offset, long[] buf, int index, int length) {
        for (int i = index; i < length; i++) {
            buf[i] = getLong((i - index) * 8L + offset);
        }
    }

    @Override
    public void read(long offset, float[] buf, int index, int length) {
    	 for (int i = index; i < length; i++) {
             buf[i] = getFloat((i - index) * 4L + offset);
         }
    }

    @Override
    public void read(long offset, double[] buf, int index, int length) {
    	  for (int i = index; i < length; i++) {
              buf[i] = getDouble((i - index) * 8L + offset);
          }
    }

    @Override
    public void read(long offset, Pointer[] buf, int index, int length) {
        throw new AbstractMethodError();
    }

    public void write(byte[] buf) {
        write(0, buf, 0, buf.length);
    }

    @Override
    public void write(long offset, byte[] buf, int index, int length) {
        if (size > 0) {
            if (offset < 0) {
                throw new IllegalArgumentException();
            }

            if (size - offset < length) {
                throw new InvalidMemoryAccessException();
            }
        }

        byte[] data;
        if (index == 0 && buf.length == length) {
            data = buf;
        } else {
            data = new byte[length];
            System.arraycopy(buf, index, data, 0, length);
        }
        long address = peer + offset;
        backend.mem_write(address, data);
        if (listener != null) {
            listener.onSystemWrite(address, data);
        }
    }

    @Override
    public void write(long offset, short[] buf, int index, int length) {
        for (int i = index; i < length; i++) {
            setShort((i - index) * 2L + offset, buf[i]);
        }
    }

    @Override
    public void write(long offset, char[] buf, int index, int length) {
        throw new AbstractMethodError();
    }

    @Override
    public void write(long offset, int[] buf, int index, int length) {
        for (int i = index; i < length; i++) {
            setInt((i - index) * 4L + offset, buf[i]);
        }
    }

    @Override
    public void write(long offset, long[] buf, int index, int length) {
        for (int i = index; i < length; i++) {
            setLong((i - index) * 8L + offset, buf[i]);
        }
    }

    @Override
    public void write(long offset, float[] buf, int index, int length) {
        for (int i = index; i < length; i++) {
            setFloat((i - index) * 4L + offset, buf[i]);
        }
    }

    @Override
    public void write(long offset, double[] buf, int index, int length) {
        for (int i = index; i < length; i++) {
            setDouble((i - index) * 8L + offset, buf[i]);
        }
    }

    @Override
    public void write(long offset, Pointer[] buf, int index, int length) {
        throw new AbstractMethodError();
    }

    @Override
    public byte getByte(long offset) {
        return getByteArray(offset, 1)[0];
    }

    @Override
    public char getChar(long offset) {
        return getByteBuffer(offset, 2).getChar();
    }

    @Override
    public short getShort(long offset) {
        return getByteBuffer(offset, 2).getShort();
    }

    @Override
    public int getInt(long offset) {
        return getByteBuffer(offset, 4).getInt();
    }

    @Override
    public long getLong(long offset) {
        return getByteBuffer(offset, 8).getLong();
    }

    @Override
    public NativeLong getNativeLong(long offset) {
        throw new AbstractMethodError();
    }

    @Override
    public float getFloat(long offset) {
        return getByteBuffer(offset, 4).getFloat();
    }

    @Override
    public double getDouble(long offset) {
        return getByteBuffer(offset, 8).getDouble();
    }

    @Override
    public UnidbgPointer getPointer(long offset) {
        return pointer(emulator, pointerSize == 4 ? (Number) getInt(offset) : (Number) getLong(offset));
    }

    @Override
    public byte[] getByteArray(long offset, int arraySize) {
        if (size > 0 && offset + arraySize > size) {
            throw new InvalidMemoryAccessException();
        }

        if (arraySize < 0 || arraySize >= 0x7ffffff) {
            throw new InvalidMemoryAccessException("Invalid array size: " + arraySize);
        }
        return backend.mem_read(peer + offset, arraySize);
    }

    @Override
    public int[] getIntArray(long offset, int arraySize) {
        if (arraySize < 0 || arraySize >= 0x7ffffff) {
            throw new InvalidMemoryAccessException("Invalid array size: " + arraySize);
        }

        int[] array = new int[arraySize];
        for (int i = 0; i < arraySize; i++) {
            array[i] = getInt(offset + i * 4);
        }
        return array;
    }

    @Override
    public ByteBuffer getByteBuffer(long offset, long length) {
        return ByteBuffer.wrap(getByteArray(offset, (int) length)).order(ByteOrder.LITTLE_ENDIAN);
    }

    @Override
    public String getWideString(long offset) {
        throw new AbstractMethodError();
    }

    @Override
    public String getString(long offset) {
        return getString(offset, "UTF-8");
    }

    @Override
    public String getString(long offset, String encoding) {
        long addr = peer + offset;

        ByteArrayOutputStream baos = new ByteArrayOutputStream(0x40);
        while (true) {
            byte[] data = backend.mem_read(addr, 0x10);
            int length = data.length;
            for (int i = 0; i < data.length; i++) {
                if (data[i] == 0) {
                    length = i;
                    break;
                }
            }
            baos.write(data, 0, length);
            addr += length;

            if (length < data.length) { // reach zero
                break;
            }

            if (baos.size() > 0x40000) { // 256k
                throw new IllegalStateException("buffer overflow");
            }

            if (size > 0 && offset + baos.size() > size) {
                throw new InvalidMemoryAccessException();
            }
        }

        try {
            String ret = baos.toString(encoding);
            log.debug("getString pointer={}, size={}, encoding={}, ret={}", this, baos.size(), encoding, ret);
            return ret;
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    private ByteBuffer allocateBuffer(int size) {
        return ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN);
    }

    @Override
    public void setMemory(long offset, long length, byte value) {
        byte[] data = new byte[(int) length];
        Arrays.fill(data, value);
        write(offset, data, 0, data.length);
    }

    @Override
    public void setByte(long offset, byte value) {
        write(offset, new byte[] { value }, 0, 1);
    }

    @Override
    public void setShort(long offset, short value) {
        write(offset, allocateBuffer(2).putShort(value).array(), 0, 2);
    }

    @Override
    public void setChar(long offset, char value) {
        write(offset, allocateBuffer(2).putChar(value).array(), 0, 2);
    }

    @Override
    public void setInt(long offset, int value) {
        write(offset, allocateBuffer(4).putInt(value).array(), 0, 4);
    }

    @Override
    public void setLong(long offset, long value) {
        write(offset, allocateBuffer(8).putLong(value).array(), 0, 8);
    }

    @Override
    public void setNativeLong(long offset, NativeLong value) {
        throw new AbstractMethodError();
    }

    @Override
    public void setFloat(long offset, float value) {
        write(offset, allocateBuffer(4).putFloat(value).array(), 0, 4);
    }

    @Override
    public void setDouble(long offset, double value) {
        write(offset, allocateBuffer(8).putDouble(value).array(), 0, 8);
    }

    @Override
    public void setPointer(long offset, Pointer pointer) {
        long value;
        if (pointer == null) {
            value = 0;
        } else {
            value = ((UnidbgPointer) pointer).peer;
        }

        if (pointerSize == 4) {
            setInt(offset, (int) value);
        } else {
            setLong(offset, value);
        }
    }

    @Override
    public void setWideString(long offset, String value) {
        throw new AbstractMethodError();
    }

    @Override
    public void setString(long offset, WString value) {
        throw new AbstractMethodError();
    }

    @Override
    public void setString(long offset, String value) {
        setString(offset, value, "UTF-8");
    }

    @Override
    public void setString(long offset, String value, String encoding) {
        try {
            byte[] data = value.getBytes(encoding);
            write(offset, Arrays.copyOf(data, data.length + 1), 0, data.length + 1);
        } catch (UnsupportedEncodingException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public UnidbgPointer share(long offset, long sz) {
        if (offset == 0L && sz == size) {
            return this;
        }

        UnidbgPointer pointer = new UnidbgPointer(emulator, peer + offset, pointerSize);
        if (size > 0) {
            if (offset > size) {
                throw new InvalidMemoryAccessException("offset=" + offset + ", size=" + size + ", peer=0x" + Long.toHexString(peer));
            }

            long newSize = size - offset;
            pointer.setSize(sz > 0 && sz < newSize ? sz : newSize);
        } else {
            pointer.setSize(sz);
        }
        return pointer;
    }

    @Override
    public String toString() {
        Memory memory = emulator == null ? null : emulator.getMemory();
        Module module = memory == null ? null : memory.findModuleByAddress(peer);
        MemoryMap memoryMap = null;
        if (memory != null) {
            for (MemoryMap mm : memory.getMemoryMap()) {
                if (peer >= mm.base && peer < mm.base + mm.size) {
                    memoryMap = mm;
                    break;
                }
            }
        }
        StringBuilder sb = new StringBuilder();
        if (memoryMap == null) {
            sb.append("unidbg");
        } else {
            boolean none = true;
            if ((memoryMap.prot & UnicornConst.UC_PROT_READ) != 0) {
                sb.append('R');
                none = false;
            }
            if ((memoryMap.prot & UnicornConst.UC_PROT_WRITE) != 0) {
                sb.append('W');
                none = false;
            }
            if ((memoryMap.prot & UnicornConst.UC_PROT_EXEC) != 0) {
                sb.append('X');
                none = false;
            }
            if (none) {
                sb.append('N');
            }
        }
        sb.append("@0x");
        sb.append(Long.toHexString(peer));
        if (module != null) {
            sb.append("[").append(module.name).append("]0x").append(Long.toHexString(peer - module.base));
        }
        return sb.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (o == null) {
            return false;
        }
        return (o instanceof UnidbgPointer) && (((UnidbgPointer)o).peer == peer);
    }

    @Override
    public int hashCode() {
        return (int)((peer >>> 32) + (peer & 0xffffffffL));
    }

    @Override
    public Pointer getPointer() {
        return this;
    }
}
