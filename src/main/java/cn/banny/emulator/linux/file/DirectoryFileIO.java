package cn.banny.emulator.linux.file;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.arm.ARM;
import cn.banny.emulator.file.AbstractFileIO;
import cn.banny.emulator.linux.IO;
import com.sun.jna.Pointer;
import unicorn.Unicorn;

import java.nio.charset.StandardCharsets;
import java.util.*;

public class DirectoryFileIO extends AbstractFileIO {

    public static class DirectoryEntry {
        private final boolean isFile;
        private final String name;
        public DirectoryEntry(boolean isFile, String name) {
            this.isFile = isFile;
            this.name = name;
        }
    }

    private final String path;

    private final List<DirectoryEntry> entries;

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
    public int fstat(Emulator emulator, Unicorn unicorn, Pointer stat) {
        int st_mode = IO.S_IFDIR | 0x777;
        /*
         * 0x00: st_dev
         * 0x18: st_uid
         * 0x1c: st_gid
         * 0x30: st_size
         * 0x38: st_blksize
         * 0x60: st_ino
         */
        stat.setLong(0x0, 0); // st_dev
        stat.setInt(0x10, st_mode); // st_mode
        stat.setLong(0x30, 0); // st_size
        stat.setInt(0x38, 0); // st_blksize
        stat.setLong(0x60, 0); // st_ino
        return 0;
    }

    @Override
    public String toString() {
        return path;
    }

}
