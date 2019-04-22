package cn.banny.emulator;

import cn.banny.emulator.linux.LinuxThread;
import cn.banny.emulator.memory.MemRegion;
import cn.banny.emulator.linux.file.ByteArrayFileIO;
import cn.banny.emulator.file.FileIO;
import cn.banny.emulator.file.IOResolver;

import java.io.IOException;
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
    public final void addIOResolver(IOResolver resolver) {
        if (!resolvers.contains(resolver)) {
            resolvers.add(0, resolver);
        }
    }

    protected final FileIO resolve(Emulator emulator, String pathname, int oflags) {
        for (IOResolver resolver : resolvers) {
            FileIO io = resolver.resolve(emulator.getWorkDir(), pathname, oflags);
            if (io != null) {
                return io;
            }
        }
        if (pathname.endsWith(".so")) {
            for (Module module : emulator.getMemory().getLoadedModules()) {
                for (MemRegion memRegion : module.getRegions()) {
                    if (pathname.equals(memRegion.getName())) {
                        try {
                            return new ByteArrayFileIO(oflags, pathname, memRegion.readLibrary());
                        } catch (IOException e) {
                            throw new IllegalStateException(e);
                        }
                    }
                }
            }
        }
        return null;
    }

}
