package net.fornwall.jelf;

public interface ElfDataIn {

    short readUnsignedByte() throws ElfException;

    short readShort() throws ElfException;

    int readInt() throws ElfException;

    long readLong() throws ElfException;

}
