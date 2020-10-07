package com.github.unidbg.ios.struct;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;
import io.kaitai.MachO;

import java.util.Arrays;
import java.util.List;

public class MachHeader extends UnidbgStructure {

    public MachHeader(Pointer p) {
        super(p);
    }

    public int magic;
    public int cpuType;
    public int cpuSubType;
    public int fileType;
    public int ncmds;
    public int sizeOfCmds;
    public int flags;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("magic", "cpuType", "cpuSubType", "fileType", "ncmds", "sizeOfCmds", "flags");
    }

    private int backupFileType;

    public boolean setExecutable() {
        if (fileType != MachO.FileType.EXECUTE.id()) {
            backupFileType = fileType;
            fileType = (int) MachO.FileType.EXECUTE.id();
            this.pack();
            return true;
        } else {
            return false;
        }
    }

    public void resetFileType() {
        fileType = backupFileType;
        this.pack();
    }

}
