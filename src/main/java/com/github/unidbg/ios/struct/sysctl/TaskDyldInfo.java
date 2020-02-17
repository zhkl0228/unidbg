package com.github.unidbg.ios.struct.sysctl;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.ios.MachOLoader;
import com.github.unidbg.ios.MachOModule;
import com.github.unidbg.ios.objc.Constants;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnicornPointer;
import com.github.unidbg.pointer.UnicornStructure;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import org.apache.commons.io.FilenameUtils;

import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

public class TaskDyldInfo extends UnicornStructure {

    private static final String DYLD_VERSION = "324.1";

    private static final int TASK_DYLD_ALL_IMAGE_INFO_32 = 0; /* format value */
    private static final int TASK_DYLD_ALL_IMAGE_INFO_64 = 1; /* format value */

    public TaskDyldInfo(Pointer p) {
        super(p);
        setAlignType(Structure.ALIGN_NONE);
    }

    public void allocateAllImage(Emulator emulator) {
        SvcMemory svcMemory = emulator.getSvcMemory();
        MachOLoader loader = (MachOLoader) emulator.getMemory();
        Collection<Module> modules = loader.getLoadedModules();
        for (Iterator<Module> iterator = modules.iterator(); iterator.hasNext(); ) {
            Module module = iterator.next();
            if (module == loader.getExecutableModule()) {
                continue;
            }
            if (module.isVirtual() || !"dylib".equals(FilenameUtils.getExtension(module.name))) {
                iterator.remove();
            }
        }

        if (emulator.is64Bit()) {
            allocateAllImage64(emulator, svcMemory, modules);
        } else {
            allocateAllImage32(emulator, svcMemory, modules);
        }
    }

    private void allocateAllImage64(Emulator emulator, SvcMemory svcMemory, Collection<Module> modules) {
        int all_image_info_size = UnicornStructure.calculateSize(DyldAllImageInfos64.class);
        this.all_image_info_format = TASK_DYLD_ALL_IMAGE_INFO_64;
        this.all_image_info_size = all_image_info_size;
        UnicornPointer all_image_info_addr = svcMemory.allocate(all_image_info_size, "DyldAllImageInfos64");
        this.all_image_info_addr = all_image_info_addr.peer;

        int size = UnicornStructure.calculateSize(DyldImageInfo64.class);
        Pointer infoArray = svcMemory.allocate(size * modules.size(), "DyldImageInfo64");
        Pointer pointer = infoArray;
        for (Module module : modules) {
            MachOModule mm = (MachOModule) module;
            DyldImageInfo64 info = new DyldImageInfo64(pointer);
            info.imageLoadAddress = UnicornPointer.pointer(emulator, mm.machHeader);
            info.imageFilePath = mm.createPathMemory(svcMemory);
            info.imageFileModDate = 0;
            info.pack();
            pointer = pointer.share(size);
        }

        DyldAllImageInfos64 infos = new DyldAllImageInfos64(all_image_info_addr);
        infos.version = 14;
        infos.infoArrayCount = modules.size();
        infos.infoArray = infoArray;
        infos.libSystemInitialized = Constants.YES;
        infos.dyldImageLoadAddress = null;
        infos.dyldVersion = svcMemory.writeStackString(DYLD_VERSION);
        infos.uuidArrayCount = 0;
        infos.uuidArray = null;
        infos.dyldAllImageInfosAddress = all_image_info_addr;
        infos.initialImageCount = modules.size();
        infos.pack();
    }

    private void allocateAllImage32(Emulator emulator, SvcMemory svcMemory, Collection<Module> modules) {
        int all_image_info_size = UnicornStructure.calculateSize(DyldAllImageInfos32.class);
        this.all_image_info_format = TASK_DYLD_ALL_IMAGE_INFO_32;
        this.all_image_info_size = all_image_info_size;
        UnicornPointer all_image_info_addr = svcMemory.allocate(all_image_info_size, "DyldAllImageInfos32");
        this.all_image_info_addr = all_image_info_addr.peer;

        int size = UnicornStructure.calculateSize(DyldImageInfo32.class);
        Pointer infoArray = svcMemory.allocate(size * modules.size(), "DyldImageInfo32");
        Pointer pointer = infoArray;
        for (Module module : modules) {
            MachOModule mm = (MachOModule) module;
            DyldImageInfo32 info = new DyldImageInfo32(pointer);
            info.imageLoadAddress = UnicornPointer.pointer(emulator, mm.machHeader);
            info.imageFilePath = mm.createPathMemory(svcMemory);
            info.imageFileModDate = 0;
            info.pack();
            pointer = pointer.share(size);
        }

        DyldAllImageInfos32 infos = new DyldAllImageInfos32(all_image_info_addr);
        infos.version = 14;
        infos.infoArrayCount = modules.size();
        infos.infoArray = infoArray;
        infos.libSystemInitialized = Constants.YES;
        infos.dyldImageLoadAddress = null;
        infos.dyldVersion = svcMemory.writeStackString(DYLD_VERSION);
        infos.uuidArrayCount = 0;
        infos.uuidArray = null;
        infos.dyldAllImageInfosAddress = all_image_info_addr;
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
