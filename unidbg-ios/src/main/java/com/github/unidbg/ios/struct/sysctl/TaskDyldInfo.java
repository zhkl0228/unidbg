package com.github.unidbg.ios.struct.sysctl;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.ios.MachOLoader;
import com.github.unidbg.ios.MachOModule;
import com.github.unidbg.ios.objc.Constants;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;

public class TaskDyldInfo extends UnidbgStructure {

    private static final Logger log = LoggerFactory.getLogger(TaskDyldInfo.class);

    private static final String DYLD_VERSION = "324.1";

    private static final int TASK_DYLD_ALL_IMAGE_INFO_32 = 0; /* format value */
    private static final int TASK_DYLD_ALL_IMAGE_INFO_64 = 1; /* format value */

    public TaskDyldInfo(Pointer p) {
        super(p);
        setAlignType(Structure.ALIGN_NONE);
    }

    private static MemoryBlock infoArrayBlock;
    private static Pointer dyldVersion;
    private static MemoryBlock dyldAllImageInfosAddressBlock;

    public void allocateAllImage(Emulator<?> emulator) {
        SvcMemory svcMemory = emulator.getSvcMemory();
        MachOLoader loader = (MachOLoader) emulator.getMemory();
        Collection<Module> modules = loader.getLoadedModules();
        modules.removeIf(Module::isVirtual);
        if (dyldVersion == null) {
            dyldVersion = svcMemory.writeStackString(DYLD_VERSION);
        }
        if (infoArrayBlock == null) {
            infoArrayBlock = loader.malloc(emulator.getPageAlign(), true);
        }
        if (dyldAllImageInfosAddressBlock == null) {
            dyldAllImageInfosAddressBlock = loader.malloc(emulator.getPageAlign(), true);
        }

        if (emulator.getSyscallHandler().isVerbose()) {
            System.out.printf("task_info TASK_DYLD_INFO called with %d modules from %s%n", modules.size(), emulator.getContext().getLRPointer());
        }
        if (log.isTraceEnabled()) {
            emulator.attach().debug();
        }

        MachOModule libdyld = (MachOModule) emulator.getMemory().findModule("libdyld.dylib");
        if (emulator.is64Bit()) {
            allocateAllImage64(svcMemory, modules, libdyld);
        } else {
            allocateAllImage32(svcMemory, modules, libdyld);
        }
    }

    private void allocateAllImage64(SvcMemory svcMemory, Collection<Module> modules, MachOModule libdyld) {
        int all_image_info_size = UnidbgStructure.calculateSize(DyldAllImageInfos64.class);

        this.all_image_info_format = TASK_DYLD_ALL_IMAGE_INFO_64;
        this.all_image_info_size = all_image_info_size;
        UnidbgPointer all_image_info_addr = dyldAllImageInfosAddressBlock.getPointer();
        this.all_image_info_addr = all_image_info_addr.peer;

        int size = UnidbgStructure.calculateSize(DyldImageInfo64.class);
        Pointer infoArray = infoArrayBlock.getPointer();
        Pointer pointer = infoArray;
        for (Module module : modules) {
            MachOModule mm = (MachOModule) module;
            DyldImageInfo64 info = new DyldImageInfo64(pointer);
            info.imageLoadAddress = mm.machHeader;
            info.imageFilePath = UnidbgPointer.nativeValue(mm.createPathMemory(svcMemory));
            info.imageFileModDate = 0;
            info.pack();
            pointer = pointer.share(size);
        }

        DyldAllImageInfos64 infos = new DyldAllImageInfos64(all_image_info_addr);
        infos.version = 14;
        infos.infoArrayCount = modules.size();
        infos.infoArray = UnidbgPointer.nativeValue(infoArray);
        infos.libSystemInitialized = Constants.YES;
        infos.dyldImageLoadAddress = libdyld == null ? 0x0L : libdyld.machHeader;
        infos.dyldVersion = UnidbgPointer.nativeValue(dyldVersion);
        infos.uuidArrayCount = 0;
        infos.uuidArray = 0L;
        infos.dyldAllImageInfosAddress = UnidbgPointer.nativeValue(all_image_info_addr);
        infos.initialImageCount = modules.size();
        infos.pack();
    }

    private void allocateAllImage32(SvcMemory svcMemory, Collection<Module> modules, MachOModule libdyld) {
        int all_image_info_size = UnidbgStructure.calculateSize(DyldAllImageInfos32.class);

        this.all_image_info_format = TASK_DYLD_ALL_IMAGE_INFO_32;
        this.all_image_info_size = all_image_info_size;
        UnidbgPointer all_image_info_addr = dyldAllImageInfosAddressBlock.getPointer();
        this.all_image_info_addr = all_image_info_addr.peer;

        int size = UnidbgStructure.calculateSize(DyldImageInfo32.class);
        Pointer infoArray = infoArrayBlock.getPointer();
        Pointer pointer = infoArray;
        for (Module module : modules) {
            MachOModule mm = (MachOModule) module;
            DyldImageInfo32 info = new DyldImageInfo32(pointer);
            info.imageLoadAddress = (int) mm.machHeader;
            info.imageFilePath = (int) UnidbgPointer.nativeValue(mm.createPathMemory(svcMemory));
            info.imageFileModDate = 0;
            info.pack();
            pointer = pointer.share(size);
        }

        DyldAllImageInfos32 infos = new DyldAllImageInfos32(all_image_info_addr);
        infos.version = 14;
        infos.infoArrayCount = modules.size();
        infos.infoArray = (int) UnidbgPointer.nativeValue(infoArray);
        infos.libSystemInitialized = Constants.YES;
        infos.dyldImageLoadAddress = libdyld == null ? 0x0 : (int) libdyld.machHeader;
        infos.dyldVersion = (int) UnidbgPointer.nativeValue(dyldVersion);
        infos.uuidArrayCount = 0;
        infos.uuidArray = 0;
        infos.dyldAllImageInfosAddress = (int) UnidbgPointer.nativeValue(all_image_info_addr);
        infos.initialImageCount = modules.size();
        infos.pack();
    }

    public long all_image_info_addr;
    public long all_image_info_size;
    public int all_image_info_format;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("all_image_info_addr", "all_image_info_size", "all_image_info_format");
    }
}
