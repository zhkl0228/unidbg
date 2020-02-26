package com.github.unidbg.linux.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.file.linux.BaseAndroidFileIO;
import com.github.unidbg.file.linux.StatStructure;
import com.github.unidbg.unix.IO;
import com.sun.jna.Pointer;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class DirectoryFileIO extends BaseAndroidFileIO {

    public static class DirectoryEntry {
        private final boolean isFile;
        private final String name;
        public DirectoryEntry(boolean isFile, String name) {
            this.isFile = isFile;
            this.name = name;
        }
    }

    private static DirectoryEntry[] createEntries(File dir) {
        List<DirectoryEntry> list = new ArrayList<>();
        File[] files = dir.listFiles();
        if (files != null) {
            Arrays.sort(files);
            for (File file : files) {
                list.add(new DirectoryEntry(file.isFile(), file.getName()));
            }
        }
        return list.toArray(new DirectoryEntry[0]);
    }

    private final String path;

    private final List<DirectoryEntry> entries;

    public DirectoryFileIO(int oflags, String path, File dir) {
        this(oflags, path, createEntries(dir));
    }

    public DirectoryFileIO(int oflags, String path, DirectoryEntry...entries) {
        super(oflags);

        this.path = path;

        this.entries = new ArrayList<>();
        this.entries.add(new DirectoryEntry(false, "."));
        this.entries.add(new DirectoryEntry(false, ".."));
        if (entries != null) {
            Collections.addAll(this.entries, entries);
        }
    }

    private static final int DT_DIR = 4;
    private static final int DT_REG = 8;

    @Override
    public int getdents64(Pointer dirp, int count) {
        int read = 0;
        Pointer entryPointer = dirp;
        for (Iterator<DirectoryEntry> iterator = this.entries.iterator(); iterator.hasNext(); ) {
            DirectoryEntry entry = iterator.next();
            byte[] data = entry.name.getBytes(StandardCharsets.UTF_8);
            long d_reclen = ARM.alignSize(data.length + 20, 8);

            entryPointer.setLong(0, 0); // d_ino
            entryPointer.setLong(8, 0); // d_off
            entryPointer.setShort(16, (short) d_reclen);
            entryPointer.setByte(18, (byte) (entry.isFile ? DT_REG : DT_DIR));
            entryPointer.write(19, Arrays.copyOf(data, data.length + 1), 0, data.length + 1);
            read += d_reclen;
            entryPointer = entryPointer.share(d_reclen);
            iterator.remove();
        }

        return read;
    }

    @Override
    public void close() {
    }

    @Override
    public int fstat(Emulator<?> emulator, StatStructure stat) {
        stat.st_mode = IO.S_IFDIR | 0x777;
        stat.st_dev = 0;
        stat.st_size = 0;
        stat.st_blksize = 0;
        stat.st_ino = 0;
        stat.pack();
        return 0;
    }

    @Override
    public String toString() {
        return path;
    }

    @Override
    public String getPath() {
        return path;
    }
}
