package com.github.unidbg.memory;

import com.github.unidbg.spi.LibraryFile;

import java.io.IOException;

public class MemRegion implements Comparable<MemRegion> {

    public final long begin;
    public final long end;
    public final int perms;
    private final LibraryFile libraryFile;
    public final long offset;

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
        return libraryFile.readToByteArray();
    }

    @Override
    public int compareTo(MemRegion o) {
        return (int) (begin - o.begin);
    }
}
