package net.fornwall.jelf;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

class ElfBuffer implements ElfDataIn {

    private final ByteBuffer buffer;

    public ElfBuffer(byte[] array) {
        buffer = ByteBuffer.wrap(array);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
    }

    @Override
    public short readUnsignedByte() throws ElfException {
        return (short) (buffer.get() & 0xff);
    }

    @Override
    public short readShort() throws ElfException {
        return buffer.getShort();
    }

    @Override
    public int readInt() throws ElfException {
        return buffer.getInt();
    }

    @Override
    public long readLong() throws ElfException {
        return buffer.getLong();
    }

}
