package cn.banny.emulator.linux.file;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.linux.MemRegion;
import cn.banny.emulator.linux.Module;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.UnicornConst;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

public class MapsFileIO extends ByteArrayFileIO implements FileIO {

    private static final Log log = LogFactory.getLog(MapsFileIO.class);

    public MapsFileIO(int oflags, String path, Collection<Module> modules) {
        super(oflags, path, getMapsData(modules));
    }

    private static byte[] getMapsData(Collection<Module> modules) {
        List<MemRegion> list = new ArrayList<>(modules.size());
        for (Module module : modules) {
            list.addAll(module.getRegions());
        }
        Collections.sort(list);
        StringBuilder builder = new StringBuilder();
        for (MemRegion memRegion : list) {
            builder.append(String.format("%08x-%08x", memRegion.begin, memRegion.end)).append(' ');
            if ((memRegion.perms & UnicornConst.UC_PROT_READ) != 0) {
                builder.append('r');
            } else {
                builder.append('-');
            }
            if ((memRegion.perms & UnicornConst.UC_PROT_WRITE) != 0) {
                builder.append('w');
            } else {
                builder.append('-');
            }
            if ((memRegion.perms & UnicornConst.UC_PROT_EXEC) != 0) {
                builder.append('x');
            } else {
                builder.append('-');
            }
            builder.append("p ");
            builder.append(String.format("%08x", memRegion.offset));
            builder.append(" b3:19 0");
            for (int i = 0; i < 10; i++) {
                builder.append(' ');
            }
            builder.append(memRegion.getName());
            builder.append('\n');
        }
        builder.append("ffff0000-ffff1000 r-xp 00000000 00:00 0          [vectors]");
        if (log.isDebugEnabled()) {
            log.debug("\n" + builder.toString());
        }

        return builder.toString().getBytes();
    }

    @Override
    public int ioctl(Emulator emulator, long request, long argp) {
        return 0;
    }
}
