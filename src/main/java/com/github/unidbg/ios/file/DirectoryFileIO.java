package com.github.unidbg.ios.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.file.ios.BaseDarwinFileIO;
import com.github.unidbg.file.ios.StatStructure;
import com.github.unidbg.ios.struct.kernel.StatFS;
import com.github.unidbg.unix.IO;
import com.sun.jna.Pointer;
import org.apache.commons.io.FilenameUtils;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class DirectoryFileIO extends BaseDarwinFileIO {

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

    private final File dir;

    public DirectoryFileIO(int oflags, String path, File dir) {
        this(oflags, path, dir, createEntries(dir));
    }

    public DirectoryFileIO(int oflags, String path, File dir, DirectoryEntry...entries) {
        super(oflags);

        this.path = path;
        this.dir = dir;

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
    public int fstatfs(StatFS statFS) {
        return 0;
    }

    @Override
    public int fstat(Emulator<?> emulator, StatStructure stat) {
        stat.st_dev = 1;
        stat.st_mode = IO.S_IFDIR | 0x777;
        stat.setSize(0);
        stat.st_blksize = 0;
        stat.st_ino = 1;
        stat.pack();
        return 0;
    }

    @Override
    public void close() {
    }

    @Override
    public String toString() {
        return path;
    }

    @Override
    public String getPath() {
        if (".".equals(path)) {
            return FilenameUtils.normalize(dir.getAbsolutePath());
        }
        return path;
    }
}
