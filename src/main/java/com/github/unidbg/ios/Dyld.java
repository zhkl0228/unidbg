package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.ios.struct.*;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnicornPointer;
import com.github.unidbg.pointer.UnicornStructure;
import com.github.unidbg.spi.Dlfcn;
import com.sun.jna.Pointer;
import io.kaitai.MachO;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

abstract class Dyld extends Dlfcn {

    private static final Log log = LogFactory.getLog(Dyld.class);

    static final int dyld_image_state_bound = 40;
    static final int dyld_image_state_dependents_initialized = 45; // Only single notification for this
    static final int dyld_image_state_initialized = 50;
    static final int dyld_image_state_terminated = 60; // Only single notification for this

    static final int RTLD_FIRST = 0x100; /* Mac OS X 10.5 and later */
    static final int RTLD_DEFAULT = (-2); /* Use default search algorithm. */
    static final int RTLD_MAIN_ONLY = (-5); /* Search main executable only (Mac OS X 10.5 and later) */

    static final int ASL_OPT_STDERR = 0x00000001;

    Dyld(SvcMemory svcMemory) {
        super(svcMemory);
    }

    abstract int _stub_binding_helper();

    static long computeSlide(Emulator emulator, long machHeader) {
        Pointer pointer = UnicornPointer.pointer(emulator, machHeader);
        assert pointer != null;
        MachHeader header = emulator.getPointerSize() == 4 ? new MachHeader(pointer) : new MachHeader64(pointer);
        header.unpack();
        Pointer loadPointer = pointer.share(header.size());
        for (int i = 0; i < header.ncmds; i++) {
            LoadCommand loadCommand = new LoadCommand(loadPointer);
            loadCommand.unpack();
            if (loadCommand.type == io.kaitai.MachO.LoadCommandType.SEGMENT.id() ||
                    loadCommand.type == MachO.LoadCommandType.SEGMENT_64.id()) {
                SegmentCommand segmentCommand = emulator.is64Bit() ? new SegmentCommand64(loadPointer) : new SegmentCommand32(loadPointer);
                segmentCommand.unpack();

                if ("__TEXT".equals(segmentCommand.getSegName())) {
                    return (machHeader - segmentCommand.getVmAddress());
                }
            }
            loadPointer = loadPointer.share(loadCommand.size);
        }
        return 0;
    }

    private String threadName = "main";

    final void pthread_setname_np(String threadName) {
        this.threadName = threadName;
        if (log.isDebugEnabled()) {
            log.debug("pthread_setname_np=" + threadName);
        }
    }

    abstract int _dyld_func_lookup(Emulator emulator, String name, Pointer address);

    long _pthread_getname_np;

    final HookStatus _pthread_getname_np(Emulator emulator) {
        RegisterContext context = emulator.getContext();
        Pointer thread = context.getPointerArg(0);
        Pointer threadName = context.getPointerArg(1);
        int len = context.getIntArg(2);
        if (log.isDebugEnabled()) {
            log.debug("_pthread_getname_np thread=" + thread + ", threadName=" + threadName + ", len=" + len);
        }
        byte[] data = Arrays.copyOf(Dyld.this.threadName.getBytes(), len);
        threadName.write(0, data, 0, data.length);
        return HookStatus.LR(emulator, 0);
    }

    protected final DyldImageInfo[] registerImageStateBatchChangeHandler(MachOLoader loader, int state, UnicornPointer handler, Emulator emulator) {
        if (log.isDebugEnabled()) {
            log.debug("registerImageStateBatchChangeHandler state=" + state + ", handler=" + handler);
        }

        if (state != dyld_image_state_bound) {
            throw new UnsupportedOperationException("state=" + state);
        }

        if (loader.boundHandlers.contains(handler)) {
            return null;
        }
        loader.boundHandlers.add(handler);
        return generateDyldImageInfo(emulator, loader, state, handler);
    }

    private DyldImageInfo[] generateDyldImageInfo(Emulator emulator, MachOLoader loader, int state, UnicornPointer handler) {
        List<DyldImageInfo> list = new ArrayList<>(loader.getLoadedModules().size());
        int elementSize = UnicornStructure.calculateSize(DyldImageInfo.class);
        Pointer pointer = emulator.getSvcMemory().allocate(elementSize * loader.getLoadedModules().size(), "DyldImageInfo");
        for (Module module : loader.getLoadedModules()) {
            MachOModule mm = (MachOModule) module;
            DyldImageInfo info = new DyldImageInfo(pointer);
            info.imageFilePath = mm.createPathMemory(emulator.getSvcMemory());
            info.imageLoadAddress = UnicornPointer.pointer(emulator, mm.machHeader);
            info.imageFileModDate = 0;
            info.pack();
            list.add(info);
            pointer = pointer.share(elementSize);

            if (state == dyld_image_state_bound) {
                mm.boundCallSet.add(handler);
            } else if (state == dyld_image_state_dependents_initialized) {
                mm.initializedCallSet.add(handler);
            }
        }
        return list.toArray(new DyldImageInfo[0]);
    }

    protected final DyldImageInfo[] registerImageStateSingleChangeHandler(MachOLoader loader, int state, UnicornPointer handler, Emulator emulator) {
        if (log.isDebugEnabled()) {
            log.debug("registerImageStateSingleChangeHandler state=" + state + ", handler=" + handler);
        }

        if (state == dyld_image_state_terminated) {
            return null;
        }

        if (state != dyld_image_state_dependents_initialized) {
            throw new UnsupportedOperationException("state=" + state);
        }

        if (loader.initializedHandlers.contains(handler)) {
            return null;
        }
        loader.initializedHandlers.add(handler);
        return generateDyldImageInfo(emulator, loader, state, handler);
    }

}
