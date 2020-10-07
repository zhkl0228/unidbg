package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.ios.ipa.IpaLoader;
import com.github.unidbg.ios.struct.*;
import com.github.unidbg.ios.struct.sysctl.DyldImageInfo32;
import com.github.unidbg.ios.struct.sysctl.DyldImageInfo64;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.pointer.UnidbgStructure;
import com.github.unidbg.spi.Dlfcn;
import com.sun.jna.Pointer;
import io.kaitai.MachO;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.ArrayList;
import java.util.List;

public abstract class Dyld extends Dlfcn {

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

    public static long computeSlide(Emulator<?> emulator, long machHeader) {
        Pointer pointer = UnidbgPointer.pointer(emulator, machHeader);
        assert pointer != null;
        MachHeader header = emulator.is32Bit() ? new MachHeader(pointer) : new MachHeader64(pointer);
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

    abstract int _dyld_func_lookup(Emulator<?> emulator, String name, Pointer address);

    protected final UnidbgStructure[] registerImageStateBatchChangeHandler(MachOLoader loader, int state, UnidbgPointer handler, Emulator<?> emulator) {
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

    private UnidbgStructure[] generateDyldImageInfo(Emulator<?> emulator, MachOLoader loader, int state, UnidbgPointer handler) {
        SvcMemory svcMemory = emulator.getSvcMemory();
        List<UnidbgStructure> list = new ArrayList<>(loader.getLoadedModulesNoVirtual().size());
        int elementSize = UnidbgStructure.calculateSize(emulator.is64Bit() ? DyldImageInfo64.class : DyldImageInfo32.class);
        Pointer pointer = svcMemory.allocate(elementSize * loader.getLoadedModulesNoVirtual().size(), "DyldImageInfo");
        List<Module> loadedModules = new ArrayList<>(loader.getLoadedModulesNoVirtual());
        for (Module module : loadedModules) {
            if (module == loader.getExecutableModule()) {
                continue;
            }
            if (module.getPath().startsWith(IpaLoader.APP_DIR)) {
                continue;
            }
            if (log.isDebugEnabled()) {
                log.debug("generateDyldImageInfo: " + module.name);
            }

            MachOModule mm = (MachOModule) module;
            if (emulator.is64Bit()) {
                DyldImageInfo64 info = new DyldImageInfo64(pointer);
                info.imageFilePath = mm.createPathMemory(svcMemory);
                info.imageLoadAddress = UnidbgPointer.pointer(emulator, mm.machHeader);
                info.imageFileModDate = 0;
                info.pack();
                list.add(info);
            } else {
                DyldImageInfo32 info = new DyldImageInfo32(pointer);
                info.imageFilePath = mm.createPathMemory(svcMemory);
                info.imageLoadAddress = UnidbgPointer.pointer(emulator, mm.machHeader);
                info.imageFileModDate = 0;
                info.pack();
                list.add(info);
            }
            pointer = pointer.share(elementSize);

            if (state == dyld_image_state_bound) {
                mm.boundCallSet.add(handler);
                mm.initializedCallSet.add(handler);
            } else if (state == dyld_image_state_dependents_initialized) {
                mm.dependentsInitializedCallSet.add(handler);
            }
        }
        return list.toArray(new UnidbgStructure[0]);
    }

    protected final UnidbgStructure[] registerImageStateSingleChangeHandler(MachOLoader loader, int state, UnidbgPointer handler, Emulator<?> emulator) {
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
