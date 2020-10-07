package com.github.unidbg.linux.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

class Ashmem extends DriverFileIO {

    private static final Log log = LogFactory.getLog(Ashmem.class);

    Ashmem(Emulator<?> emulator, int oflags, String path) {
        super(emulator, oflags, path);
    }

    private static final int ASHMEM_SET_NAME = 0x41007701;
    private static final int ASHMEM_SET_SIZE = 0x40047703;

    private String name;
    private int size;

    @Override
    public int ioctl(Emulator<?> emulator, long request, long argp) {
        if (request == ASHMEM_SET_NAME) {
            Pointer pointer = UnidbgPointer.pointer(emulator, argp);
            assert pointer != null;
            this.name = pointer.getString(0);
            log.debug("ashmem set name: " + this.name);
            return 0;
        }
        if (request == ASHMEM_SET_SIZE) {
            this.size = (int) argp;
            log.debug("ashmem set size: " + this.size);
            return 0;
        }

        return super.ioctl(emulator, request, argp);
    }

    @Override
    protected byte[] getMmapData(int offset, int length) {
        return new byte[0];
    }

    @Override
    public String toString() {
        return "Ashmem{" +
                "name='" + name + '\'' +
                ", size=" + size +
                '}';
    }
}
