package com.github.unidbg.linux.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.file.UnidbgFileFilter;
import com.github.unidbg.file.linux.BaseAndroidFileIO;
import com.github.unidbg.file.linux.StatStructure;
import com.github.unidbg.linux.struct.Dirent;
import com.github.unidbg.linux.struct.StatFS;
import com.github.unidbg.unix.IO;
import com.sun.jna.Pointer;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class DirectoryFileIO extends BaseAndroidFileIO {

    public enum DirentType {
        DT_FIFO(1), /* FIFO */
        DT_CHR(2), /* character device */
        DT_DIR(4), /* directory */
        DT_BLK(6), /* block device */
        DT_REG(8), /* regular file */
        DT_LNK(10), /* symbolic link */
        DT_SOCK(12), /* socket */
        DT_WHT(14); /* whiteout */
        private final byte type;
        DirentType(int type) {
            this.type = (byte) type;
        }
    }

    public static class DirectoryEntry {
        private final DirentType type;
        private final String name;
        public DirectoryEntry(boolean isFile, String name) {
            this(isFile ? DirentType.DT_REG : DirentType.DT_DIR, name);
        }
        public DirectoryEntry(DirentType type, String name) {
            this.type = type;
            this.name = name;
        }
    }

    private static DirectoryEntry[] createEntries(File dir) {
        List<DirectoryEntry> list = new ArrayList<>();
        File[] files = dir.listFiles(new UnidbgFileFilter());
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

    @Override
    public int getdents64(Pointer dirp, int size) {
        int offset = 0;
        for (Iterator<DirectoryEntry> iterator = this.entries.iterator(); iterator.hasNext(); ) {
            DirectoryEntry entry = iterator.next();
            byte[] data = entry.name.getBytes(StandardCharsets.UTF_8);
            long d_reclen = ARM.alignSize(data.length + 24, 8);

            if (offset + d_reclen >= size) {
                break;
            }

            Dirent dirent = new Dirent(dirp.share(offset));
            dirent.d_ino = 0;
            dirent.d_off = 0;
            dirent.d_reclen = (short) d_reclen;
            dirent.d_type = entry.type.type;
            dirent.d_name = Arrays.copyOf(data, data.length + 1);
            dirent.pack();
            offset += d_reclen;

            iterator.remove();
        }

        return offset;
    }

    @Override
    public void close() {
    }

    @Override
    public int fstat(Emulator<?> emulator, StatStructure stat) {
        stat.st_mode = IO.S_IFDIR;
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

    @Override
    public int statfs(StatFS statFS) {
        statFS.setType(0xef53);
        statFS.setBlockSize(0x1000);
        statFS.f_blocks = 0x3235af;
        statFS.f_bfree = 0x2b5763;
        statFS.f_bavail = 0x2b5763;
        statFS.f_files = 0xcccb0;
        statFS.f_ffree = 0xcbd2e;
        statFS.f_fsid = new int[] { 0xd3609fe8, 0x4970d6b };
        statFS.setNameLen(0xff);
        statFS.setFrSize(0x1000);
        statFS.setFlags(0x426);
        statFS.pack();
        return 0;
    }
}
