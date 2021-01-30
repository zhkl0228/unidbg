package com.github.unidbg.memory;

import com.github.unidbg.Emulator;
import com.github.unidbg.spi.LibraryFile;

import java.io.IOException;
import java.nio.ByteBuffer;

public class MemRegion implements Comparable<MemRegion> {

    public final long begin;
    public final long end;
    public final int perms;
    private final LibraryFile libraryFile;
    public final long offset;

    public static MemRegion create(long begin, int size, int perms, final String name) {
        return new MemRegion(begin, begin + size, perms, new LibraryFile() {
            @Override
            public String getName() {
                return name;
            }
            @Override
            public String getMapRegionName() {
                return name;
            }
            @Override
            public LibraryFile resolveLibrary(Emulator<?> emulator, String soName) {
                throw new UnsupportedOperationException();
            }
            @Override
            public ByteBuffer mapBuffer() {
                throw new UnsupportedOperationException();
            }
            @Override
            public String getPath() {
                return name;
            }
        }, 0);
    }

    public MemRegion(long begin, long end, int perms, LibraryFile libraryFile, long offset) {
        this.begin = begin;
        this.end = end;
        this.perms = perms;
        this.libraryFile = libraryFile;
        this.offset = offset;
    }

    public String getName() {
        return libraryFile.getMapRegionName();
    }

    public byte[] readLibrary() throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public int compareTo(MemRegion o) {
        return Long.compare(begin, o.begin);
    }
}
