package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.Symbol;
import com.github.unidbg.hook.HookListener;
import com.sun.jna.Pointer;
import io.kaitai.struct.ByteBufferKaitaiStream;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.nio.charset.StandardCharsets;
import java.util.List;

final class FixupChains {

    private static final Log log = LogFactory.getLog(FixupChains.class);

    // values for dyld_chained_fixups_header.imports_format
    static final int DYLD_CHAINED_IMPORT = 1;
    static final int DYLD_CHAINED_IMPORT_ADDEND = 2;
    static final int DYLD_CHAINED_IMPORT_ADDEND64 = 3;

    static final int DYLD_CHAINED_PTR_START_NONE = 0xffff; // used in page_start[] to denote a page with no fixups
    static final int DYLD_CHAINED_PTR_START_MULTI = 0x8000; // used in page_start[] to denote a page which has multiple starts
    static final int DYLD_CHAINED_PTR_START_LAST = 0x8000; // used in chain_starts[] to denote last start in list for page

    // values for dyld_chained_starts_in_segment.pointer_format
    static final int DYLD_CHAINED_PTR_ARM64E = 1; // stride 8, unauth target is vmaddr
    static final int DYLD_CHAINED_PTR_64 = 2; // target is vmaddr
    static final int DYLD_CHAINED_PTR_32 = 3;
    static final int DYLD_CHAINED_PTR_32_CACHE = 4;
    static final int DYLD_CHAINED_PTR_32_FIRMWARE = 5;
    static final int DYLD_CHAINED_PTR_64_OFFSET = 6; // target is vm offset
    static final int DYLD_CHAINED_PTR_ARM64E_OFFSET = 7; // stride 4, unauth target is vm offset
    static final int DYLD_CHAINED_PTR_64_KERNEL_CACHE = 8;
    static final int DYLD_CHAINED_PTR_ARM64E_USERLAND = 9; // stride 8, unauth target is vm offset
    static final int DYLD_CHAINED_PTR_ARM64E_FIRMWARE = 10; // stride 4, unauth target is vmaddr
    static final int DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE = 11; // stride 1, x86_64 kernel caches
    static final int DYLD_CHAINED_PTR_ARM64E_USERLAND24 = 12; // stride 8, unauth target is vm offset, 24-bit bind

    static boolean greaterThanAddOrOverflow(long addLHS, long addRHS, long b) {
        return (addLHS > b) || (addRHS > (b-addLHS));
    }

    private static long signExtendedAddend(long addend) {
        long top8Bits = addend & 0x00007f80000L;
        long bottom19Bits = addend & 0x0000007ffffL;
        return (top8Bits << 13) | (((bottom19Bits << 37) >>> 37) & 0x00ffffffffffffffL);
    }

    static void handleChain(Emulator<?> emulator, MachOModule mm, List<HookListener> hookListeners, int pointer_format, Pointer chain, long raw64, List<BindTarget> bindTargets, ByteBufferKaitaiStream symbolsPool) {
        switch (pointer_format) {
            case DYLD_CHAINED_PTR_64:
            case DYLD_CHAINED_PTR_64_OFFSET:
                long newValue;
                boolean bind = (raw64 >>> 63) != 0;
                if (bind) {
                    int ordinal = (int) (raw64 & 0xffffff);
                    long addend = (raw64 >> 24) & 0xff;
                    if (ordinal >= bindTargets.size()) {
                        throw new IllegalStateException(String.format("out of range bind ordinal %d (max %d)", ordinal, bindTargets.size()));
                    } else {
                        BindTarget bindTarget = bindTargets.get(ordinal);
                        newValue = bindTarget.bind(emulator, mm, hookListeners, symbolsPool) + signExtendedAddend(addend);
                        chain.setLong(0, newValue);
                    }
                } else {
                    long target = raw64 & 0xfffffffffL;
                    long high8 = (raw64 >> 36) & 0xff;

                    // plain rebase (old format target is vmaddr, new format target is offset)
                    long unpackedTarget = (high8 << 56) | target;
                    if (pointer_format == DYLD_CHAINED_PTR_64) {
                        chain.setLong(0, unpackedTarget);
                    } else {
                        throw new UnsupportedOperationException("DYLD_CHAINED_PTR_64_OFFSET");
                    }
                }
                break;
            default:
                throw new UnsupportedOperationException("pointer_format=" + pointer_format);
        }
    }

    static abstract class BindTarget implements MachO {
        protected abstract long bind(Emulator<?> emulator, MachOModule mm, List<HookListener> hookListeners, ByteBufferKaitaiStream symbolsPool);
        final Symbol resolveSymbol(MachOLoader loader, MachOModule mm, int libraryOrdinal, String symbolName, boolean weak) {
            if (libraryOrdinal > 0) {
                if (libraryOrdinal > mm.ordinalList.size()) {
                    throw new IllegalStateException("ordinal-too-large");
                }
                String path = mm.ordinalList.get(libraryOrdinal - 1);
                MachOModule targetImage = loader.modules.get(FilenameUtils.getName(path));
                targetImage = loader.fakeTargetImage(targetImage, symbolName);
                if (targetImage == null && weak) {
                    return null;
                }
                if (targetImage == null) {
                    log.info("resolveSymbol libraryOrdinal=" + libraryOrdinal + ", symbolName=" + symbolName);
                    return null;
                }
                return loader.findSymbolInternal(targetImage, symbolName);
            } else {
                switch (libraryOrdinal) {
                    case BIND_SPECIAL_DYLIB_SELF:
                        throw new UnsupportedOperationException("BIND_SPECIAL_DYLIB_SELF");
                    case BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE:
                        throw new UnsupportedOperationException("BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE");
                    case BIND_SPECIAL_DYLIB_FLAT_LOOKUP:
                        throw new UnsupportedOperationException("BIND_SPECIAL_DYLIB_FLAT_LOOKUP");
                    case BIND_SPECIAL_DYLIB_WEAK_LOOKUP:
                        Symbol symbol = null;
                        for (MachOModule module : loader.modules.values().toArray(new MachOModule[0])) {
                            if (module.hasWeakDefines()) {
                                symbol = module.findSymbolByName(symbolName, false);
                                if (symbol != null) {
                                    break;
                                }
                            }
                        }
                        if (symbol == null && weak) {
                            return null;
                        }
                        if (symbol != null) {
                            return symbol;
                        }
                        throw new UnsupportedOperationException("BIND_SPECIAL_DYLIB_WEAK_LOOKUP");
                    default:
                        throw new UnsupportedOperationException("unknown-ordinal");
                }
            }
        }
    }

    static class dyld_chained_import_addend64 extends BindTarget {
        final int lib_ordinal;
        final boolean weak_import;
        final int name_offset;
        final long addend;
        public dyld_chained_import_addend64(int lib_ordinal, boolean weak_import, int name_offset, long addend) {
            this.lib_ordinal = lib_ordinal;
            this.weak_import = weak_import;
            this.name_offset = name_offset;
            this.addend = addend;
        }
        @Override
        protected long bind(Emulator<?> emulator, MachOModule mm, List<HookListener> hookListeners, ByteBufferKaitaiStream symbolsPool) {
            symbolsPool.seek(name_offset);
            String symbolName = new String(symbolsPool.readBytesTerm(0, false, true, true), StandardCharsets.US_ASCII);
            MachOLoader loader = (MachOLoader) emulator.getMemory();
            Symbol symbol = resolveSymbol(loader, mm, lib_ordinal, symbolName, weak_import);
            if (symbol == null) {
                if (log.isDebugEnabled()) {
                    log.info("bind symbolName=" + symbolName + ", lib_ordinal=" + lib_ordinal);
                }
                long bindAt = 0;
                for (HookListener listener : hookListeners) {
                    long hook = listener.hook(emulator.getSvcMemory(), mm.name, symbolName, HookListener.FIXUP_BIND);
                    if (hook > 0) {
                        bindAt = hook;
                        break;
                    }
                }
                return bindAt;
            }
            long bindAt = symbol.getAddress() + addend;
            for (HookListener listener : hookListeners) {
                long hook = listener.hook(emulator.getSvcMemory(), symbol.getModuleName(), symbol.getName(), bindAt);
                if (hook > 0) {
                    bindAt = hook;
                    break;
                }
            }
            return bindAt;
        }
    }

}
