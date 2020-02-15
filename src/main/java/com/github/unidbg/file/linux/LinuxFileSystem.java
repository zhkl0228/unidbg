package com.github.unidbg.file.linux;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.BaseFileSystem;
import com.github.unidbg.file.FileIO;
import com.github.unidbg.file.FileSystem;
import com.github.unidbg.linux.file.MapsFileIO;
import com.github.unidbg.linux.file.NullFileIO;

import java.io.File;

public class LinuxFileSystem extends BaseFileSystem implements FileSystem, IOConstants {

    public LinuxFileSystem(Emulator emulator, File rootDir) {
        super(emulator, rootDir);
    }

    @Override
    public FileIO open(String pathname, int oflags) {
        if ("/dev/tty".equals(pathname)) {
            return new NullFileIO(pathname);
        }
        if ("/proc/self/maps".equals(pathname) || ("/proc/" + emulator.getPid() + "/maps").equals(pathname)) {
            return new MapsFileIO(oflags, pathname, emulator.getMemory().getLoadedModules());
        }

        return super.open(pathname, oflags);
    }

    @Override
    protected boolean hasCreat(int oflags) {
        return (oflags & O_CREAT) != 0;
    }

    @Override
    protected boolean hasDirectory(int oflags) {
        return (oflags & O_DIRECTORY) != 0;
    }

    @Override
    protected boolean hasAppend(int oflags) {
        return (oflags & O_APPEND) != 0;
    }

}
