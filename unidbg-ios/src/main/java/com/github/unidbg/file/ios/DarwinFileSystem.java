package com.github.unidbg.file.ios;

import com.dd.plist.NSDictionary;
import com.dd.plist.PropertyListParser;
import com.github.unidbg.Emulator;
import com.github.unidbg.file.BaseFileSystem;
import com.github.unidbg.file.FileSystem;
import com.github.unidbg.ios.file.DirectoryFileIO;
import com.github.unidbg.ios.file.SimpleFileIO;
import com.github.unidbg.ios.file.Stdin;
import com.github.unidbg.ios.file.Stdout;
import com.github.unidbg.unix.IO;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.util.Collections;

public class DarwinFileSystem extends BaseFileSystem<DarwinFileIO> implements FileSystem<DarwinFileIO>, IOConstants {

    public DarwinFileSystem(Emulator<DarwinFileIO> emulator, File rootDir) {
        super(emulator, rootDir);
    }

    @Override
    protected void initialize(File rootDir) throws IOException {
        super.initialize(rootDir);

        FileUtils.forceMkdir(new File(rootDir, "private"));
        FileUtils.forceMkdir(new File(rootDir, "var/root/Library"));
        FileUtils.forceMkdir(new File(rootDir, "var/root/Documents"));

        File plist = new File(rootDir, "var/root/Library/Preferences/.GlobalPreferences.plist");
        FileUtils.forceMkdir(plist.getParentFile());
        if (!plist.exists()) {
            NSDictionary root = (NSDictionary) NSDictionary.fromJavaObject(Collections.emptyMap());
            PropertyListParser.saveAsASCII(root, plist);
        }
    }

    @Override
    public DarwinFileIO createSimpleFileIO(File file, int oflags, String path) {
        return new SimpleFileIO(oflags, file, path);
    }

    @Override
    public DarwinFileIO createDirectoryFileIO(File file, int oflags, String path) {
        return new DirectoryFileIO(oflags, path, file);
    }

    @Override
    protected DarwinFileIO createStdin(int oflags) {
        return new Stdin(oflags);
    }

    @Override
    protected DarwinFileIO createStdout(int oflags, File stdio, String pathname) {
        return new Stdout(oflags, stdio, pathname, IO.STDERR.equals(pathname), null);
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

    @Override
    protected boolean hasExcl(int oflags) {
        return (oflags & O_EXCL) != 0;
    }

    public void config(String bundleIdentifier) {
        File plist = new File(rootDir, "var/root/Library/Preferences/" + bundleIdentifier + ".plist");
        try {
            FileUtils.forceMkdir(plist.getParentFile());
            if (!plist.exists()) {
                NSDictionary root = (NSDictionary) NSDictionary.fromJavaObject(Collections.emptyMap());
                PropertyListParser.saveAsASCII(root, plist);
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

}
