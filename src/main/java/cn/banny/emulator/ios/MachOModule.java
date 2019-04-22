package cn.banny.emulator.ios;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.Module;
import cn.banny.emulator.Symbol;
import cn.banny.emulator.memory.MemRegion;

import java.io.IOException;
import java.util.List;
import java.util.Map;

public class MachOModule extends Module {

    public MachOModule(String name, long base, long size, Map<String, Module> neededLibraries, List<MemRegion> regions) {
        super(name, base, size, neededLibraries, regions);
    }

    @Override
    public Number[] callFunction(Emulator emulator, long offset, Object... args) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Symbol findSymbolByName(String name, boolean withDependencies) throws IOException {
        throw new UnsupportedOperationException();
    }

}
