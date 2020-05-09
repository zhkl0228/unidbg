package com.github.unidbg.ios.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.file.ios.BaseDarwinFileIO;
import com.github.unidbg.file.ios.StatStructure;
import com.github.unidbg.ios.struct.Dirent;
import com.github.unidbg.ios.struct.attr.AttrList;
import com.github.unidbg.ios.struct.attr.FinderInfo;
import com.github.unidbg.ios.struct.attr.UserAccess;
import com.github.unidbg.ios.struct.kernel.StatFS;
import com.github.unidbg.pointer.UnicornPointer;
import com.github.unidbg.pointer.UnicornStructure;
import com.github.unidbg.unix.IO;
import com.github.unidbg.unix.struct.TimeSpec;
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
    public int fcntl(Emulator<?> emulator, int cmd, long arg) {
        if (cmd == F_GETPATH) {
            UnicornPointer pointer = UnicornPointer.pointer(emulator, arg);
            if (pointer != null) {
                pointer.setString(0, getPath());
            }
            return 0;
        }

        return super.fcntl(emulator, cmd, arg);
    }

    @Override
    public String getPath() {
        if (".".equals(path)) {
            return FilenameUtils.normalize(dir.getAbsolutePath());
        }
        return path;
    }

    @Override
    public int getattrlist(AttrList attrList, Pointer attrBuf, int attrBufSize) {
        if (attrList.bitmapcount != ATTR_BIT_MAP_COUNT) {
            throw new UnsupportedOperationException("bitmapcount=" + attrList.bitmapcount);
        }
        Pointer pointer = attrBuf.share(4);
        List<UnicornStructure> list = new ArrayList<>();
        if((attrList.commonattr & ATTR_CMN_CRTIME) != 0) {
            TimeSpec timeSpec = new TimeSpec(pointer);
            pointer = pointer.share(timeSpec.size());
            list.add(timeSpec);
            attrList.commonattr &= ~ATTR_CMN_CRTIME;
        }
        if ((attrList.commonattr & ATTR_CMN_FNDRINFO) != 0) {
            FinderInfo finderInfo = new FinderInfo(pointer);
            pointer = pointer.share(finderInfo.size());
            list.add(finderInfo);
            attrList.commonattr &= ~ATTR_CMN_FNDRINFO;
        }
        if ((attrList.commonattr & ATTR_CMN_USERACCESS) != 0) {
            UserAccess userAccess = new UserAccess(pointer);
            userAccess.mode = X_OK | W_OK | R_OK;
//            pointer = pointer.share(userAccess.size());
            list.add(userAccess);
            attrList.commonattr &= ~ATTR_CMN_USERACCESS;
        }
        if (attrList.commonattr != 0 || attrList.volattr != 0 ||
                attrList.dirattr != 0 || attrList.fileattr != 0 ||
                attrList.forkattr != 0) {
            return -1;
        }
        int len = 0;
        for (UnicornStructure structure : list) {
            len += structure.size();
            structure.pack();
        }
        attrBuf.setInt(0, len + 4);
        return 0;
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
}
