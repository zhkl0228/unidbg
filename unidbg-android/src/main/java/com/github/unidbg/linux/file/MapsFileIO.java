package com.github.unidbg.linux.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.file.FileIO;
import com.github.unidbg.memory.MemRegion;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import unicorn.UnicornConst;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

public class MapsFileIO extends ByteArrayFileIO implements FileIO {

    private static final Logger log = LoggerFactory.getLogger(MapsFileIO.class);

    public MapsFileIO(Emulator<?> emulator, int oflags, String path, Collection<Module> modules) {
        super(oflags, path, getMapsData(emulator, modules, null));
    }

    @SuppressWarnings("unused")
    protected MapsFileIO(Emulator<?> emulator, int oflags, String path, Collection<Module> modules, String additionContent) {
        this(oflags, path, getMapsData(emulator, modules, additionContent));
    }

    protected MapsFileIO(int oflags, String path, byte[] bytes) {
        super(oflags, path, bytes);
    }

    protected static byte[] getMapsData(Emulator<?> emulator, Collection<Module> modules, String additionContent) {
        List<MemRegion> list = new ArrayList<>(modules.size());
        for (Module module : modules) {
            list.addAll(module.getRegions());
        }
        Collections.sort(list);
        List<MapItem> items = new ArrayList<>();
        for (MemRegion memRegion : list) {
            items.add(new MapItem(memRegion.virtualAddress, memRegion.end, memRegion.perms, 0, "b3:19", memRegion.getName()));
        }
        long stackSize = (long) Memory.STACK_SIZE_OF_PAGE * emulator.getPageAlign();
        items.add(new MapItem(Memory.STACK_BASE - stackSize, Memory.STACK_BASE, UnicornConst.UC_PROT_WRITE | UnicornConst.UC_PROT_READ, 0, "00:00", "[stack]"));

        List<MapItem> mapItems = new ArrayList<>();
        for (MemoryMap memoryMap : emulator.getMemory().getMemoryMap()) {
            boolean contains = false;
            for (MapItem item : items) {
                if (Math.max(memoryMap.base, item.start) <= Math.min(memoryMap.base + memoryMap.size, item.end)) {
                    contains = true;
                    break;
                }
            }
            if (!contains) {
                mapItems.add(new MapItem(memoryMap.base, memoryMap.base + memoryMap.size, memoryMap.prot, 0, "00:00", "anonymous"));
            }
        }
        items.addAll(mapItems);

        StringBuilder builder = new StringBuilder();
        for (MapItem item : items) {
            builder.append(item);
        }
        if (additionContent != null) {
            builder.append(additionContent).append('\n');
        }
        if (log.isDebugEnabled()) {
            log.debug("\n{}", builder);
        }

        return builder.toString().getBytes();
    }

    private static class MapItem {
        private final long start;
        private final long end;
        private final int perms;
        private final int offset;
        private final String device;
        private final String label;
        public MapItem(long start, long end, int perms, int offset, String device, String label) {
            this.start = start;
            this.end = end;
            this.perms = perms;
            this.offset = offset;
            this.device = device;
            this.label = label;
        }
        @Override
        public String toString() {
            StringBuilder builder = new StringBuilder();
            builder.append(String.format("%08x-%08x", start, end)).append(' ');
            if ((perms & UnicornConst.UC_PROT_READ) != 0) {
                builder.append('r');
            } else {
                builder.append('-');
            }
            if ((perms & UnicornConst.UC_PROT_WRITE) != 0) {
                builder.append('w');
            } else {
                builder.append('-');
            }
            if ((perms & UnicornConst.UC_PROT_EXEC) != 0) {
                builder.append('x');
            } else {
                builder.append('-');
            }
            builder.append("p ");
            builder.append(String.format("%08x", offset));
            builder.append(" ").append(device).append(" 0");
            for (int i = 0; i < 10; i++) {
                builder.append(' ');
            }
            builder.append(label);
            builder.append('\n');
            return builder.toString();
        }
    }

    @Override
    public int ioctl(Emulator<?> emulator, long request, long argp) {
        return 0;
    }
}
