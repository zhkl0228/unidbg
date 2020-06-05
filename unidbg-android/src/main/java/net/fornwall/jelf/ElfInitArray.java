package net.fornwall.jelf;

public class ElfInitArray {

    public final long[] array;

    ElfInitArray(final ElfParser parser, long offset, int size) {
        parser.seek(offset);

        if (parser.elfFile.objectSize == ElfFile.CLASS_32) {
            array = new long[size / 4];
            for (int i = 0; i < array.length; i++) {
                array[i] = parser.readInt();
            }
        } else {
            array = new long[size / 8];
            for (int i = 0; i < array.length; i++) {
                array[i] = parser.readLong();
            }
        }
    }

}
