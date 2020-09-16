package com.github.unidbg.linux;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.file.linux.IOConstants;
import com.github.unidbg.linux.struct.StatFS;
import com.github.unidbg.linux.struct.StatFS32;
import com.github.unidbg.linux.struct.StatFS64;
import com.github.unidbg.spi.SyscallHandler;
import com.github.unidbg.unix.UnixEmulator;
import com.github.unidbg.unix.UnixSyscallHandler;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

abstract class AndroidSyscallHandler extends UnixSyscallHandler<AndroidFileIO> implements SyscallHandler<AndroidFileIO> {

    private static final Log log = LogFactory.getLog(AndroidSyscallHandler.class);

    protected long statfs64(Emulator<AndroidFileIO> emulator, String path, Pointer buf) {
        FileResult<AndroidFileIO> result = resolve(emulator, path, IOConstants.O_RDONLY);
        if (result == null) {
            log.info("statfs64 buf=" + buf + ", path=" + path);
            emulator.getMemory().setErrno(UnixEmulator.ENOENT);
            return -1;
        }
        if (result.isSuccess()) {
            StatFS statFS = emulator.is64Bit() ? new StatFS64(buf) : new StatFS32(buf);
            int ret = result.io.statfs(statFS);
            if (ret != 0) {
                log.info("statfs64 buf=" + buf + ", path=" + path);
            } else {
                if (verbose) {
                    System.out.println(String.format("File statfs '%s' from %s", result.io, emulator.getContext().getLRPointer()));
                }
                if (log.isDebugEnabled()) {
                    log.debug("statfs64 buf=" + buf + ", path=" + path);
                }
            }
            return ret;
        } else {
            log.info("statfs64 buf=" + buf + ", path=" + path);
            emulator.getMemory().setErrno(result.errno);
            return -1;
        }
    }

}
