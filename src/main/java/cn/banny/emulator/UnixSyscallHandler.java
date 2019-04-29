package cn.banny.emulator;

import cn.banny.auxiliary.Inspector;
import cn.banny.emulator.file.FileIO;
import cn.banny.emulator.file.IOResolver;
import cn.banny.emulator.linux.IO;
import cn.banny.emulator.linux.LinuxEmulator;
import cn.banny.emulator.linux.LinuxThread;
import cn.banny.emulator.linux.file.*;
import cn.banny.emulator.memory.MemRegion;
import cn.banny.emulator.pointer.TimeVal;
import cn.banny.emulator.pointer.TimeZone;
import cn.banny.emulator.spi.SyscallHandler;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;
import java.util.*;

public abstract class UnixSyscallHandler implements SyscallHandler {

    private static final Log log = LogFactory.getLog(UnixSyscallHandler.class);

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
        if (pathname.endsWith(emulator.getLibraryExtension())) {
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

    protected final int gettimeofday(Pointer tv, Pointer tz) {
        if (log.isDebugEnabled()) {
            log.debug("gettimeofday tv=" + tv + ", tz=" + tz);
        }

        if (log.isDebugEnabled()) {
            byte[] before = tv.getByteArray(0, 8);
            Inspector.inspect(before, "gettimeofday tv");
        }
        if (tz != null && log.isDebugEnabled()) {
            byte[] before = tz.getByteArray(0, 8);
            Inspector.inspect(before, "gettimeofday tz");
        }

        long currentTimeMillis = System.currentTimeMillis();
        long tv_sec = currentTimeMillis / 1000;
        long tv_usec = (currentTimeMillis % 1000) * 1000;
        TimeVal timeVal = new TimeVal(tv);
        timeVal.tv_sec = (int) tv_sec;
        timeVal.tv_usec = (int) tv_usec;
        timeVal.pack();

        if (tz != null) {
            Calendar calendar = Calendar.getInstance();
            int tz_minuteswest = -(calendar.get(Calendar.ZONE_OFFSET) + calendar.get(Calendar.DST_OFFSET)) / (60 * 1000);
            cn.banny.emulator.pointer.TimeZone timeZone = new TimeZone(tz);
            timeZone.tz_minuteswest = tz_minuteswest;
            timeZone.tz_dsttime = 0;
            timeZone.pack();
        }

        if (log.isDebugEnabled()) {
            byte[] after = tv.getByteArray(0, 8);
            Inspector.inspect(after, "gettimeofday tv after tv_sec=" + tv_sec + ", tv_usec=" + tv_usec);
        }
        if (tz != null && log.isDebugEnabled()) {
            byte[] after = tz.getByteArray(0, 8);
            Inspector.inspect(after, "gettimeofday tz after");
        }
        return 0;
    }

    protected final int sigprocmask(Emulator emulator, int how, Pointer set, Pointer oldset) {
        if (log.isDebugEnabled()) {
            log.debug("sigprocmask how=" + how + ", set=" + set + ", oldset=" + oldset);
        }
        emulator.getMemory().setErrno(LinuxEmulator.EINVAL);
        return -1;
    }

    protected final int read(Emulator emulator, int fd, Pointer buffer, int count) {
        if (log.isDebugEnabled()) {
            log.debug("read fd=" + fd + ", buffer=" + buffer + ", count=" + count);
        }

        FileIO file = fdMap.get(fd);
        if (file == null) {
            emulator.getMemory().setErrno(LinuxEmulator.EBADF);
            return -1;
        }
        return file.read(emulator.getUnicorn(), buffer, count);
    }

    @Override
    public final int open(Emulator emulator, String pathname, int oflags) {
        int minFd = this.getMinFd();

        FileIO io = resolve(emulator, pathname, oflags);
        if (io != null) {
            this.fdMap.put(minFd, io);
            return minFd;
        }

        if ("/dev/tty".equals(pathname)) {
            io = new NullFileIO(pathname);
            this.fdMap.put(minFd, io);
            return minFd;
        }

        if ("/proc/self/maps".equals(pathname) || ("/proc/" + emulator.getPid() + "/maps").equals(pathname)) {
            io = new MapsFileIO(oflags, pathname, emulator.getMemory().getLoadedModules());
            this.fdMap.put(minFd, io);
            return minFd;
        }
        FileIO driverIO = DriverFileIO.create(oflags, pathname);
        if (driverIO != null) {
            this.fdMap.put(minFd, driverIO);
            return minFd;
        }
        if (IO.STDIN.equals(pathname)) {
            io = new Stdin(oflags);
            this.fdMap.put(minFd, io);
            return minFd;
        }

        emulator.getMemory().setErrno(LinuxEmulator.EACCES);
        return -1;
    }

}
