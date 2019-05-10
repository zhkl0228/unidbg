package cn.banny.emulator.ios;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.ios.struct.LoadCommand;
import cn.banny.emulator.ios.struct.MachHeader;
import cn.banny.emulator.ios.struct.SegmentCommand;
import cn.banny.emulator.pointer.UnicornPointer;
import cn.banny.emulator.spi.Dlfcn;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public abstract class Dyld implements Dlfcn {

    private static final Log log = LogFactory.getLog(Dyld.class);

    static final int dyld_image_state_bound = 40;
    static final int dyld_image_state_dependents_initialized = 45; // Only single notification for this
    static final int dyld_image_state_terminated = 60; // Only single notification for this

    abstract int _stub_binding_helper();

    static int computeSlide(Emulator emulator, long machHeader) {
        if (emulator.getPointerSize() == 4) {
            Pointer pointer = UnicornPointer.pointer(emulator, machHeader);
            assert pointer != null;
            MachHeader header = new MachHeader(pointer);
            Pointer loadPointer = pointer.share(header.size());
            for (int i = 0; i < header.ncmds; i++) {
                LoadCommand loadCommand = new LoadCommand(loadPointer);
                loadCommand.unpack();
                if (loadCommand.type == io.kaitai.MachO.LoadCommandType.SEGMENT.id()) {
                    SegmentCommand segmentCommand = new SegmentCommand(loadPointer);
                    segmentCommand.unpack();

                    if ("__TEXT".equals(new String(segmentCommand.segname).trim())) {
                        return (int) (machHeader - segmentCommand.vmaddr);
                    }
                }
                loadPointer = loadPointer.share(loadCommand.size);
            }
            return 0;
        } else {
            throw new UnsupportedOperationException();
        }
    }

    String threadName = "main";

    void pthread_setname_np(String threadName) {
        this.threadName = threadName;
        if (log.isDebugEnabled()) {
            log.debug("pthread_setname_np=" + threadName);
        }
    }

    abstract int _dyld_func_lookup(Emulator emulator, String name, Pointer address);

}
