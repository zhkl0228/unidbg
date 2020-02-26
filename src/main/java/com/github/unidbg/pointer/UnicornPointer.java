package com.github.unidbg.pointer;

import com.github.unidbg.Emulator;
import com.github.unidbg.InvalidMemoryAccessException;
import com.github.unidbg.Module;
import com.github.unidbg.hook.BaseHook;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryMap;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.WString;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Unicorn;
import unicorn.UnicornConst;

import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class UnicornPointer extends Pointer {

    private static final Log log = LogFactory.getLog(UnicornPointer.class);

    private final Emulator<?> emulator;
    private final Unicorn unicorn;
    public final long peer;
    private final int pointerSize;

    public long toUIntPeer() {
        return peer & 0xffffffffL;
    }

    private UnicornPointer(Emulator<?> emulator, long peer, int pointerSize) {
        super(0);

        this.emulator = emulator;
        this.unicorn = emulator.getUnicorn();
        this.peer = peer;
        this.pointerSize = pointerSize;
    }

    private long size;

    public UnicornPointer setSize(long size) {
        if (size < 0) {
            throw new IllegalArgumentException("size=" + size);
        }
        this.size = size;
        return this;
    }

    public long getSize() {
        return size;
    }

    public static UnicornPointer pointer(Emulator<?> emulator, long addr) {
        return addr == 0 ? null : new UnicornPointer(emulator, addr, emulator.getPointerSize());
    }

    public static UnicornPointer pointer(Emulator<?> emulator, Number number) {
        return pointer(emulator, BaseHook.numberToAddress(emulator, number));
    }

    public static UnicornPointer register(Emulator<?> emulator, int reg) {
        return pointer(emulator, (Number) emulator.getUnicorn().reg_read(reg));
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
            buf[i] = getInt((i - index) * 4 + offset);
        }
    }

    @Override
    public void read(long offset, long[] buf, int index, int length) {
        for (int i = index; i < length; i++) {
            buf[i] = getLong((i - index) * 8 + offset);
        }
    }

    @Override
    public void read(long offset, float[] buf, int index, int length) {
    	 for (int i = index; i < length; i++) {
             buf[i] = getFloat((i - index) * 4 + offset);
         }
    }

    @Override
    public void read(long offset, double[] buf, int index, int length) {
    	  for (int i = index; i < length; i++) {
              buf[i] = getDouble((i - index) * 8 + offset);
          }
    }

    @Override
    public void read(long offset, Pointer[] buf, int index, int length) {
        throw new AbstractMethodError();
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

        if (index == 0 && buf.length == length) {
            unicorn.mem_write(peer + offset, buf);
        } else {
            byte[] data = new byte[length];
            System.arraycopy(buf, index, data, 0, length);
            unicorn.mem_write(peer + offset, data);
        }
    }

    @Override
    public void write(long offset, short[] buf, int index, int length) {
        throw new AbstractMethodError();
    }

    @Override
    public void write(long offset, char[] buf, int index, int length) {
        throw new AbstractMethodError();
    }

    @Override
    public void write(long offset, int[] buf, int index, int length) {
        for (int i = index; i < length; i++) {
            setInt((i - index) * 4 + offset, buf[i]);
        }
    }

    @Override
    public void write(long offset, long[] buf, int index, int length) {
        for (int i = index; i < length; i++) {
            setLong((i - index) * 8 + offset, buf[i]);
        }
    }

    @Override
    public void write(long offset, float[] buf, int index, int length) {
        for (int i = index; i < length; i++) {
            setFloat((i - index) * 4 + offset, buf[i]);
        }
    }

    @Override
    public void write(long offset, double[] buf, int index, int length) {
        throw new AbstractMethodError();
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
    public UnicornPointer getPointer(long offset) {
        return pointer(emulator, pointerSize == 4 ? (Number) getInt(offset) : (Number) getLong(offset));
    }

    @Override
    public byte[] getByteArray(long offset, int arraySize) {
        if (size > 0 && offset + arraySize > size) {
            throw new InvalidMemoryAccessException();
        }

        return unicorn.mem_read(peer + offset, arraySize);
    }

    @Override
    public int[] getIntArray(long offset, int arraySize) {
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

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        while (true) {
            byte[] data = unicorn.mem_read(addr, 0x10);
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

            if (baos.size() > 0x10000) { // 64k
                throw new IllegalStateException("buffer overflow");
            }

            if (size > 0 && offset + baos.size() > size) {
                throw new InvalidMemoryAccessException();
            }
        }

        try {
            String ret = baos.toString(encoding);
            log.debug("getString pointer=" + this + ", size=" + baos.size() + ", encoding=" + encoding + ", ret=" + ret);
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
            value = ((UnicornPointer) pointer).peer;
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
    public UnicornPointer share(long offset, long sz) {
        if (offset == 0L && sz == size) {
            return this;
        }

        UnicornPointer pointer = new UnicornPointer(emulator, peer + offset, pointerSize);
        if (size > 0) {
            if (offset > size) {
                throw new InvalidMemoryAccessException("offset=" + offset + ", size=" + size);
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
            sb.append("unicorn");
        } else {
            if ((memoryMap.prot & UnicornConst.UC_PROT_READ) != 0) {
                sb.append('R');
            }
            if ((memoryMap.prot & UnicornConst.UC_PROT_WRITE) != 0) {
                sb.append('W');
            }
            if ((memoryMap.prot & UnicornConst.UC_PROT_EXEC) != 0) {
                sb.append('X');
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
        return (o instanceof UnicornPointer) && (((UnicornPointer)o).peer == peer);
    }

    @Override
    public int hashCode() {
        return (int)((peer >>> 32) + (peer & 0xffffffffL));
    }

}
