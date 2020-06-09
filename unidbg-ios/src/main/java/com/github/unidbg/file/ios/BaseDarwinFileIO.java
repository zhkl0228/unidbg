package com.github.unidbg.file.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.BaseFileIO;
import com.github.unidbg.ios.file.DirectoryFileIO;
import com.github.unidbg.ios.struct.attr.*;
import com.github.unidbg.ios.struct.kernel.StatFS;
import com.github.unidbg.pointer.UnicornStructure;
import com.github.unidbg.unix.struct.TimeSpec;
import com.sun.jna.Pointer;
import org.apache.commons.io.FilenameUtils;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public abstract class BaseDarwinFileIO extends BaseFileIO implements DarwinFileIO {

    public BaseDarwinFileIO(int oflags) {
        super(oflags);
    }

    public int fstat(Emulator<?> emulator, StatStructure stat) {
        throw new UnsupportedOperationException(getClass().getName());
    }

    @Override
    public int fcntl(Emulator<?> emulator, int cmd, long arg) {
        if (cmd == F_NOCACHE) {
            return 0;
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
        List<UnicornStructure> list = new ArrayList<>();
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
        for (UnicornStructure structure : list) {
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
    public int getdirentries64(Pointer buf, int bufSize) {
        throw new UnsupportedOperationException(getClass().getName());
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
