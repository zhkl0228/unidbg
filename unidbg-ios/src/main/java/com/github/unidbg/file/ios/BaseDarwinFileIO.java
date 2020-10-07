package com.github.unidbg.file.ios;

import com.alibaba.fastjson.JSON;
import com.github.unidbg.Emulator;
import com.github.unidbg.file.BaseFileIO;
import com.github.unidbg.ios.file.DirectoryFileIO;
import com.github.unidbg.ios.struct.attr.*;
import com.github.unidbg.ios.struct.kernel.StatFS;
import com.github.unidbg.pointer.UnidbgStructure;
import com.github.unidbg.unix.UnixEmulator;
import com.github.unidbg.unix.struct.TimeSpec;
import com.sun.jna.Pointer;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

public abstract class BaseDarwinFileIO extends BaseFileIO implements DarwinFileIO {

    private static final Log log = LogFactory.getLog(BaseDarwinFileIO.class);

    public BaseDarwinFileIO(int oflags) {
        super(oflags);
    }

    public int fstat(Emulator<?> emulator, StatStructure stat) {
        throw new UnsupportedOperationException(getClass().getName());
    }

    private int protectionClass;

    @Override
    public int fcntl(Emulator<?> emulator, int cmd, long arg) {
        if (cmd == F_NOCACHE) {
            return 0;
        }
        if (cmd == F_SETPROTECTIONCLASS) {
            protectionClass = (int) arg;
            return 0;
        }
        if (cmd == F_GETPROTECTIONCLASS) {
            return protectionClass;
        }

        return super.fcntl(emulator, cmd, arg);
    }

    public int fstatfs(StatFS statFS) {
        throw new UnsupportedOperationException(getClass().getName());
    }

    @Override
    public int getattrlist(AttrList attrList, Pointer attrBuf, int attrBufSize) {
        if (attrList.bitmapcount != ATTR_BIT_MAP_COUNT) {
            throw new UnsupportedOperationException("bitmapcount=" + attrList.bitmapcount);
        }
        Pointer pointer = attrBuf.share(4);
        List<UnidbgStructure> list = new ArrayList<>();
        List<AttrReference> attrReferenceList = new ArrayList<>();
        if((attrList.commonattr & ATTR_CMN_NAME) != 0) {
            String name = FilenameUtils.getName(getPath());
            byte[] bytes = name.getBytes(StandardCharsets.UTF_8);
            AttrReference attrReference = new AttrReference(pointer, bytes);
            attrReferenceList.add(attrReference);
            pointer = pointer.share(attrReference.size());
            list.add(attrReference);
            attrList.commonattr &= ~ATTR_CMN_NAME;
        }
        if((attrList.commonattr & ATTR_CMN_DEVID) != 0) {
            Dev dev = new Dev(pointer);
            dev.dev = 1;
            pointer = pointer.share(dev.size());
            list.add(dev);
            attrList.commonattr &= ~ATTR_CMN_DEVID;
        }
        if((attrList.commonattr & ATTR_CMN_FSID) != 0) {
            Fsid fsid = new Fsid(pointer);
            fsid.val[0] = 0;
            fsid.val[1] = 0;
            pointer = pointer.share(fsid.size());
            list.add(fsid);
            attrList.commonattr &= ~ATTR_CMN_FSID;
        }
        if((attrList.commonattr & ATTR_CMN_OBJTYPE) != 0) {
            ObjType objType = new ObjType(pointer);
            objType.type = this instanceof DirectoryFileIO ? vtype.VDIR.ordinal() : vtype.VREG.ordinal();
            pointer = pointer.share(objType.size());
            list.add(objType);
            attrList.commonattr &= ~ATTR_CMN_OBJTYPE;
        }
        if((attrList.commonattr & ATTR_CMN_OBJID) != 0) {
            ObjId objId = new ObjId(pointer);
            objId.fid_objno = 0;
            objId.fid_generation = 0;
            pointer = pointer.share(objId.size());
            list.add(objId);
            attrList.commonattr &= ~ATTR_CMN_OBJID;
        }
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
        for (UnidbgStructure structure : list) {
            int size = structure.size();
            len += size;
            structure.pack();

            for (AttrReference attrReference : attrReferenceList) {
                attrReference.check(structure, size);
            }
        }
        attrBuf.setInt(0, len + 4);

        for (AttrReference attrReference : attrReferenceList) {
            pointer = attrBuf.share(attrReference.attr_dataoffset + 4);
            attrReference.writeAttr(pointer);
        }

        return 0;
    }

    @Override
    public int setattrlist(AttrList attrList, Pointer attrBuf, int attrBufSize) {
        if (attrList.bitmapcount != ATTR_BIT_MAP_COUNT) {
            throw new UnsupportedOperationException("bitmapcount=" + attrList.bitmapcount);
        }
        Pointer pointer = attrBuf.share(4);
        if((attrList.commonattr & ATTR_CMN_CRTIME) != 0) {
            TimeSpec timeSpec = new TimeSpec(pointer);
            pointer = pointer.share(timeSpec.size());
            if (log.isDebugEnabled()) {
                log.debug("setattrlist timeSpec=" + timeSpec + ", pointer=" + pointer);
            }
            attrList.commonattr &= ~ATTR_CMN_CRTIME;
        }
        if ((attrList.commonattr & ATTR_CMN_FNDRINFO) != 0) {
            FinderInfo finderInfo = new FinderInfo(pointer);
            pointer = pointer.share(finderInfo.size());
            if (log.isDebugEnabled()) {
                log.debug("setattrlist finderInfo=" + finderInfo + ", pointer=" + pointer);
            }
            attrList.commonattr &= ~ATTR_CMN_FNDRINFO;
        }
        if (attrList.commonattr != 0 || attrList.volattr != 0 ||
                attrList.dirattr != 0 || attrList.fileattr != 0 ||
                attrList.forkattr != 0) {
            return -1;
        }
        return 0;
    }

    @Override
    public int getdirentries64(Pointer buf, int bufSize) {
        throw new UnsupportedOperationException(getClass().getName());
    }

    @Override
    public int listxattr(Pointer namebuf, int size, int options) {
        throw new UnsupportedOperationException(getClass().getName());
    }

    @Override
    public int setxattr(String name, byte[] data) {
        throw new UnsupportedOperationException(getClass().getName());
    }

    @Override
    public int getxattr(Emulator<?> emulator, String name, Pointer value, int size) {
        throw new UnsupportedOperationException(getClass().getName());
    }

    @Override
    public int chown(int uid, int gid) {
        throw new UnsupportedOperationException(getClass().getName());
    }

    @Override
    public int chmod(int mode) {
        throw new UnsupportedOperationException(getClass().getName());
    }

    @Override
    public int chflags(int flags) {
        throw new UnsupportedOperationException(getClass().getName());
    }

    protected final int chflags(File dest, int flags) {
        try {
            DarwinFileAttr attr = loadAttr(dest);
            if (attr == null) {
                attr = new DarwinFileAttr();
            }
            attr.flags = flags;
            File file = createAttrFile(dest);
            FileUtils.writeStringToFile(file, JSON.toJSONString(attr));
            return 0;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    protected final int chmod(File dest, int mode) {
        try {
            DarwinFileAttr attr = loadAttr(dest);
            if (attr == null) {
                attr = new DarwinFileAttr();
            }
            attr.mode = mode;
            File file = createAttrFile(dest);
            FileUtils.writeStringToFile(file, JSON.toJSONString(attr));
            return 0;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    protected final int chown(File dest, int uid, int gid) {
        try {
            DarwinFileAttr attr = loadAttr(dest);
            if (attr == null) {
                attr = new DarwinFileAttr();
            }
            attr.uid = uid;
            attr.gid = gid;
            File file = createAttrFile(dest);
            FileUtils.writeStringToFile(file, JSON.toJSONString(attr));
            return 0;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    protected final DarwinFileAttr loadAttr(File dest) throws IOException {
        File file = createAttrFile(dest);
        if (file.exists()) {
            return JSON.parseObject(FileUtils.readFileToString(file), DarwinFileAttr.class);
        } else {
            return null;
        }
    }

    protected final int listxattr(File dest, Pointer namebuf, int size) {
        try {
            DarwinFileAttr attr = loadAttr(dest);
            if (attr == null || attr.xattr == null) {
                return 0;
            }
            int ret = 0;
            Pointer buffer = namebuf;
            for (String name : attr.xattr.keySet()) {
                byte[] data = name.getBytes(StandardCharsets.UTF_8);
                ret += (data.length + 1);

                if (buffer != null && ret <= size) {
                    buffer.write(0, Arrays.copyOf(data, data.length + 1), 0, data.length + 1);
                    buffer = buffer.share(data.length + 1);
                }
            }
            return ret;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    protected final int getxattr(Emulator<?> emulator, File dest, String name, Pointer value, int size) {
        try {
            DarwinFileAttr attr = loadAttr(dest);
            byte[] data = attr == null || attr.xattr == null ? null : attr.xattr.get(name);
            if (data == null) {
                emulator.getMemory().setErrno(UnixEmulator.ENOATTR);
                return -1;
            }
            if (value == null) {
                return data.length;
            } else if (size >= data.length) {
                value.write(0, data, 0, data.length);
                return data.length;
            } else {
                value.write(0, data, 0, size);
                return size;
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    protected final int setxattr(File dest, String name, byte[] data) {
        try {
            DarwinFileAttr attr = loadAttr(dest);
            if (attr == null) {
                attr = new DarwinFileAttr();
            }
            if (attr.xattr == null) {
                attr.xattr = new HashMap<>();
            }
            attr.xattr.put(name, data);
            File file = createAttrFile(dest);
            FileUtils.writeStringToFile(file, JSON.toJSONString(attr));
            return 0;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    protected void setFlags(long arg) {
        if ((IOConstants.O_APPEND & arg) != 0) {
            oflags |= IOConstants.O_APPEND;
        }
        if ((IOConstants.O_RDWR & arg) != 0) {
            oflags |= IOConstants.O_RDWR;
        }
        if ((IOConstants.O_NONBLOCK & arg) != 0) {
            oflags |= IOConstants.O_NONBLOCK;
        }
    }
}
