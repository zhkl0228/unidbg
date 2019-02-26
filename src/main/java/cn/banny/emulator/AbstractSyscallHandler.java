package cn.banny.emulator;

import cn.banny.emulator.linux.LinuxThread;
import cn.banny.emulator.linux.file.FileIO;
import cn.banny.emulator.linux.file.IOResolver;

import java.io.File;
import java.util.*;

public abstract class AbstractSyscallHandler implements SyscallHandler {

    private final List<IOResolver> resolvers = new ArrayList<>(5);

    public final Map<Integer, FileIO> fdMap = new TreeMap<>();

    public final Map<Integer, LinuxThread> threadMap = new HashMap<>(5);
    public int lastThread = -1;

    protected final int getMinFd() {
        int last_fd = -1;
        for (int fd : fdMap.keySet()) {
            if (last_fd + 1 == fd) {
                last_fd = fd;
            } else {
                break;
            }
        }
        return last_fd + 1;
    }

    @Override
    public final void addIOResolve(IOResolver resolver) {
        if (!resolvers.contains(resolver)) {
            resolvers.add(0, resolver);
        }
    }

    protected final FileIO resolve(File workDir, String pathname, int oflags) {
        for (IOResolver resolver : resolvers) {
            FileIO io = resolver.resolve(workDir, pathname, oflags);
            if (io != null) {
                return io;
            }
        }
        return null;
    }

}
