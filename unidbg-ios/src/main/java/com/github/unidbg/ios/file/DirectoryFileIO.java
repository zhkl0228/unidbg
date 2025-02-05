package com.github.unidbg.ios.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.file.UnidbgFileFilter;
import com.github.unidbg.file.ios.BaseDarwinFileIO;
import com.github.unidbg.file.ios.StatStructure;
import com.github.unidbg.ios.struct.Dirent;
import com.github.unidbg.ios.struct.kernel.StatFS;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.unix.IO;
import com.sun.jna.Pointer;

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

    private final File dir;

    public DirectoryFileIO(int oflags, String path, File dir) {
        this(oflags, path, dir, createEntries(dir));
    }

    public DirectoryFileIO(int oflags, String path, DirectoryEntry... entries) {
        this(oflags, path, null, entries);
    }

    public DirectoryFileIO(int oflags, String path, File dir, DirectoryEntry... entries) {
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

    @Override
    public int fstatfs(StatFS statFS) {
        return 0;
    }

    @Override
    public int fstat(Emulator<?> emulator, StatStructure stat) {
        stat.st_dev = 1;
        stat.st_mode = IO.S_IFDIR | 0x777;
        stat.setSize(dir == null ? 0 : dir.getTotalSpace());
        stat.st_blksize = 0;
        stat.st_ino = 7;
        stat.st_uid = 0;
        stat.st_gid = 0;
        if (dir != null) {
            stat.setLastModification(dir.lastModified());
        }
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
    public int fcntl(Emulator<?> emulator, int cmd, long arg) {
        if (cmd == F_GETPATH) {
            UnidbgPointer pointer = UnidbgPointer.pointer(emulator, arg);
            if (pointer != null) {
                pointer.setString(0, getPath());
            }
            return 0;
        }

        return super.fcntl(emulator, cmd, arg);
    }

    @Override
    public String getPath() {
        return path;
    }

    @Override
    public int getdirentries64(Pointer buf, int bufSize) {
        int offset = 0;
        for (Iterator<DirectoryFileIO.DirectoryEntry> iterator = this.entries.iterator(); iterator.hasNext(); ) {
            DirectoryFileIO.DirectoryEntry entry = iterator.next();
            byte[] data = entry.name.getBytes(StandardCharsets.UTF_8);
            long d_reclen = ARM.alignSize(data.length + 24, 8);

            if (offset + d_reclen >= bufSize) {
                break;
            }

            Dirent dirent = new Dirent(buf.share(offset));
            dirent.d_fileno = 1;
            dirent.d_reclen = (short) d_reclen;
            dirent.d_type = entry.isFile ? Dirent.DT_REG : Dirent.DT_DIR;
            dirent.d_namlen = (short) (data.length);
            dirent.d_name = Arrays.copyOf(data, data.length + 1);
            dirent.pack();
            offset += d_reclen;

            iterator.remove();
        }

        return offset;
    }

    @Override
    public int listxattr(Pointer namebuf, int size, int options) {
        if (dir == null) {
            throw new UnsupportedOperationException("path=" + path + ", options=0x" + Integer.toHexString(options));
        }
        return listxattr(dir, namebuf, size);
    }

    @Override
    public int removexattr(String name) {
        if (dir == null) {
            throw new UnsupportedOperationException("path=" + path + ", name=" + name);
        }
        return removexattr(dir, name);
    }

    @Override
    public int setxattr(String name, byte[] data) {
        if (dir == null) {
            throw new UnsupportedOperationException("path=" + path + ", name=" + name);
        }
        return setxattr(dir, name, data);
    }

    @Override
    public int getxattr(Emulator<?> emulator, String name, Pointer value, int size) {
        if (dir == null) {
            throw new UnsupportedOperationException("path=" + path + ", name=" + name);
        }
        return getxattr(emulator, dir, name, value, size);
    }

    @Override
    public int chmod(int mode) {
        if (dir == null) {
            throw new UnsupportedOperationException("path=" + path + ", mode=0x" + Integer.toHexString(mode));
        }
        return chmod(dir, mode);
    }

    @Override
    public int chown(int uid, int gid) {
        if (dir == null) {
            throw new UnsupportedOperationException("path=" + path + ", uid=" + uid + ", gid=" + gid);
        }
        return chown(dir, uid, gid);
    }

    @Override
    public int chflags(int flags) {
        if (dir == null) {
            throw new UnsupportedOperationException("path=" + path + ", flags=0x" + Integer.toHexString(flags));
        }
        return chflags(dir, flags);
    }
}
