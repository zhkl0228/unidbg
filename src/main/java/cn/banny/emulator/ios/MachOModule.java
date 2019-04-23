package cn.banny.emulator.ios;

import cn.banny.emulator.*;
import cn.banny.emulator.memory.MemRegion;
import cn.banny.emulator.pointer.UnicornPointer;
import io.kaitai.MachO;
import io.kaitai.struct.ByteBufferKaitaiStream;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MachOModule extends Module {

    final MachO machO;
    private final MachO.SymtabCommand symtabCommand;
    final MachO.DysymtabCommand dysymtabCommand;
    private final ByteBuffer buffer;
    final List<NeedLibrary> lazyLoadNeededList;
    final Map<String, Module> upwardLibraries;

    private final Map<String, MachOSymbol> symbolMap = new HashMap<>();

    MachOModule(MachO machO, String name, long base, long size, Map<String, Module> neededLibraries, List<MemRegion> regions,
                MachO.SymtabCommand symtabCommand, MachO.DysymtabCommand dysymtabCommand, ByteBuffer buffer,
                List<NeedLibrary> lazyLoadNeededList, Map<String, Module> upwardLibraries) {
        super(name, base, size, neededLibraries, regions);
        this.machO = machO;
        this.symtabCommand = symtabCommand;
        this.dysymtabCommand = dysymtabCommand;
        this.buffer = buffer;
        this.lazyLoadNeededList = lazyLoadNeededList;
        this.upwardLibraries = upwardLibraries;

        if (symtabCommand != null) {
            buffer.limit((int) (symtabCommand.strOff() + symtabCommand.strSize()));
            buffer.position((int) symtabCommand.strOff());
            ByteBuffer strBuffer = buffer.slice();
            ByteBufferKaitaiStream io = new ByteBufferKaitaiStream(strBuffer);
            for (MachO.SymtabCommand.Nlist nlist : symtabCommand.symbols()) {
                if (nlist.sect() == NO_SECT || nlist.un() == 0) {
                    continue;
                }

                strBuffer.position((int) nlist.un());
                String symbolName = new String(io.readBytesTerm(0, false, true, true), Charset.forName("ascii"));
                Log log = LogFactory.getLog(name);
                if (log.isDebugEnabled()) {
                    log.debug("nlist64 un=0x" + Long.toHexString(nlist.un()) + ", name=" + name + ", symbolName=" + symbolName + ", type=0x" + Long.toHexString(nlist.type()) + ", sect=" + nlist.sect() + ", desc=" + nlist.desc() + ", value=0x" + Long.toHexString(nlist.value()));
                }

                symbolMap.put(symbolName, new MachOSymbol(this, nlist, symbolName));
            }
        }
    }

    final Map<String, Module> neededLibraries() {
        return neededLibraries;
    }

    @Override
    public Number[] callFunction(Emulator emulator, long offset, Object... args) {
        return emulateFunction(emulator, base + offset, args);
    }

    private static Number[] emulateFunction(Emulator emulator, long address, Object... args) {
        List<Number> list = new ArrayList<>(args.length);
        for (Object arg : args) {
            if (arg instanceof String) {
                list.add(new StringNumber((String) arg));
            } else if(arg instanceof byte[]) {
                list.add(new ByteArrayNumber((byte[]) arg));
            } else if(arg instanceof UnicornPointer) {
                UnicornPointer pointer = (UnicornPointer) arg;
                list.add(pointer.peer);
            } else if (arg instanceof Number) {
                list.add((Number) arg);
            } else if(arg == null) {
                list.add(0); // null
            } else {
                throw new IllegalStateException("Unsupported arg: " + arg);
            }
        }
        return emulator.eFunc(address, list.toArray(new Number[0]));
    }

    MachOSymbol getSymbolByIndex(int index) {
        buffer.limit((int) (symtabCommand.strOff() + symtabCommand.strSize()));
        buffer.position((int) symtabCommand.strOff());
        ByteBuffer strBuffer = buffer.slice();
        ByteBufferKaitaiStream io = new ByteBufferKaitaiStream(strBuffer);

        MachO.SymtabCommand.Nlist nlist = symtabCommand.symbols().get(index);
        strBuffer.position((int) nlist.un());
        String symbolName = new String(io.readBytesTerm(0, false, true, true), Charset.forName("ascii"));
        return new MachOSymbol(this, nlist, symbolName);
    }

    private static final int NO_SECT = 0;

    @Override
    public Symbol findSymbolByName(String name, boolean withDependencies) throws IOException {
        Symbol symbol = symbolMap.get(name);
        if (symbol != null) {
            return symbol;
        }

        if (withDependencies) {
            return findDependencySymbolByName(name);
        }
        return null;
    }

    @Override
    public String toString() {
        return "MachOModule{" +
                "name='" + name + '\'' +
                '}';
    }
}
