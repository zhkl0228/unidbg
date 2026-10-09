package com.github.unidbg.linux.thread;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.FileIO;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.linux.file.TcpSocket;
import com.github.unidbg.thread.AbstractWaiter;
import com.sun.jna.Pointer;
import unicorn.Arm64Const;
import unicorn.ArmConst;

import java.util.Map;

public class PPollWaiter extends AbstractWaiter {

    private final int nfds;
    private final Emulator<?> emulator;
    private final Pointer fds;
    private final Pointer tmo_p;
    private final Pointer sigmask;
    private final Map<Integer, AndroidFileIO> fdMap;
    private final long endWaitTimeInMillis;

    public PPollWaiter(Emulator<?> emulator, Pointer fds, int nfds, Pointer tmo_p, Pointer sigmask,
                       Map<Integer, AndroidFileIO> fdMap) {
        this.emulator = emulator;
        this.fds = fds;
        this.nfds = nfds;
        this.tmo_p = tmo_p;
        this.sigmask = sigmask;
        this.fdMap = fdMap;
        long tv_sec = tmo_p.getLong(0);
        long tv_nsec = tmo_p.getLong(8);
        this.endWaitTimeInMillis = System.currentTimeMillis() + (
                tv_sec * 1000L + tv_nsec / 1000000L
                );
    }

    private static final short POLLIN = 0x0001;
    private static final short POLLOUT = 0x0004;

    @Override
    public boolean canDispatch() {
        int count = 0;
        for (int i = 0; i < nfds; i++) {
            Pointer pollfd = fds.share(i * 8L);
            int fd = pollfd.getInt(0);
            short events = pollfd.getShort(4); // requested events
            if (fd >= 0) {
                short revents = 0;
                FileIO io = fdMap.get(fd);
                if ((events & POLLOUT) != 0 && io.canWrite()) {
                    revents = POLLOUT;
                } else if ((events & POLLIN) != 0 && io.canRead()) {
                    revents = POLLIN;
                }
                if (revents != 0) {
                    pollfd.setShort(6, revents); // returned events
                    count++;
                }
            }
        }

        return count > 0 || System.currentTimeMillis() > endWaitTimeInMillis;
    }

    @Override
    public void onContinueRun(Emulator<?> emulator) {

        int count = 0;
        for (int i = 0; i < nfds; i++) {
            Pointer pollfd = fds.share(i * 8L);
            int fd = pollfd.getInt(0);
            short events = pollfd.getShort(4); // requested events
            if (fd < 0) {
                pollfd.setShort(6, (short) 0);
            } else {
                short revents = 0;
                FileIO io = fdMap.get(fd);
                if ((events & POLLOUT) != 0 && io.canWrite()) {
                    revents = POLLOUT;
                } else if ((events & POLLIN) != 0 && io.canRead()) {
                    revents = POLLIN;
                }
                if (revents != 0) {
                    pollfd.setShort(6, revents); // returned events
                    count++;
                }
            }
        }

        emulator.getBackend().reg_write(emulator.is32Bit() ? ArmConst.UC_ARM_REG_R0 : Arm64Const.UC_ARM64_REG_X0,
                count);
    }
}
