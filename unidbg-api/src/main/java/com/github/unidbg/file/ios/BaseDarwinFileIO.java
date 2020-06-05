package com.github.unidbg.file.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.BaseFileIO;
import com.github.unidbg.ios.struct.attr.AttrList;
import com.github.unidbg.ios.struct.attr.FinderInfo;
import com.github.unidbg.ios.struct.attr.UserAccess;
import com.github.unidbg.ios.struct.kernel.StatFS;
import com.github.unidbg.pointer.UnicornStructure;
import com.github.unidbg.unix.struct.TimeSpec;
import com.sun.jna.Pointer;

import java.util.ArrayList;
import java.util.List;

public abstract class BaseDarwinFileIO extends BaseFileIO implements DarwinFileIO {

    public BaseDarwinFileIO(int oflags) {
        super(oflags);
    }

    public int fstat(Emulator<?> emulator, StatStructure stat) {
        throw new UnsupportedOperationException(getClass().getName());
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
