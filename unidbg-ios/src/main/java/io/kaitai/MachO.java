// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

package io.kaitai;

import io.kaitai.struct.ByteBufferKaitaiStream;
import io.kaitai.struct.KaitaiStruct;
import io.kaitai.struct.KaitaiStream;
import java.io.IOException;
import java.util.Map;
import java.util.HashMap;
import java.util.ArrayList;
import java.nio.charset.Charset;

public class MachO extends KaitaiStruct {
    public static MachO fromFile(String fileName) throws IOException {
        return new MachO(new ByteBufferKaitaiStream(fileName));
    }

    public enum MagicType {
        FAT_LE(0xbebafecaL),
        FAT_BE(0xcafebabeL),
        MACHO_LE_X86(0xcefaedfeL),
        MACHO_LE_X64(0xcffaedfeL),
        MACHO_BE_X86(0xfeedfaceL),
        MACHO_BE_X64(0xfeedfacfL);

        private final long id;
        MagicType(long id) { this.id = id; }
        public long id() { return id; }
        private static final Map<Long, MagicType> byId = new HashMap<Long, MagicType>(6);
        static {
            for (MagicType e : MagicType.values())
                byId.put(e.id(), e);
        }
        public static MagicType byId(long id) { return byId.get(id); }
    }

    public enum CpuType {
        VAX(0x1L),
        ROMP(0x2L),
        NS32032(0x4L),
        NS32332(0x5L),
        I386(0x7L),
        MIPS(0x8L),
        NS32532(0x9L),
        HPPA(0xbL),
        ARM(0xcL),
        MC88000(0xdL),
        SPARC(0xeL),
        I860(0xfL),
        I860_LITTLE(0x10L),
        RS6000(0x11L),
        POWERPC(0x12L),
        ABI64(0x1000000L),
        X86_64(0x1000007L),
        ARM64(0x100000cL),
        POWERPC64(0x1000012L),
        ANY(0xffffffffL);

        private final long id;
        CpuType(long id) { this.id = id; }
        public long id() { return id; }
        private static final Map<Long, CpuType> byId = new HashMap<Long, CpuType>(20);
        static {
            for (CpuType e : CpuType.values())
                byId.put(e.id(), e);
        }
        public static CpuType byId(long id) { return byId.get(id); }
    }

    public enum FileType {
        OBJECT(0x1L),
        EXECUTE(0x2L),
        FVMLIB(0x3L),
        CORE(0x4L),
        PRELOAD(0x5L),
        DYLIB(0x6L),
        DYLINKER(0x7L),
        BUNDLE(0x8L),
        DYLIB_STUB(0x9L),
        DSYM(0xaL),
        KEXT_BUNDLE(0xbL);

        private final long id;
        FileType(long id) { this.id = id; }
        public long id() { return id; }
        private static final Map<Long, FileType> byId = new HashMap<Long, FileType>(11);
        static {
            for (FileType e : FileType.values())
                byId.put(e.id(), e);
        }
        public static FileType byId(long id) { return byId.get(id); }
    }

    public enum LoadCommandType {
        SEGMENT(0x1L),
        SYMTAB(0x2L),
        SYMSEG(0x3L),
        THREAD(0x4L),
        UNIX_THREAD(0x5L),
        LOAD_FVM_LIB(0x6L),
        ID_FVM_LIB(0x7L),
        IDENT(0x8L),
        FVM_FILE(0x9L),
        PREPAGE(0xaL),
        DYSYMTAB(0xbL),
        LOAD_DYLIB(0xcL),
        ID_DYLIB(0xdL),
        LOAD_DYLINKER(0xeL),
        ID_DYLINKER(0xfL),
        PREBOUND_DYLIB(0x10L),
        ROUTINES(0x11L),
        SUB_FRAMEWORK(0x12L),
        SUB_UMBRELLA(0x13L),
        SUB_CLIENT(0x14L),
        SUB_LIBRARY(0x15L),
        TWOLEVEL_HINTS(0x16L),
        PREBIND_CKSUM(0x17L),
        SEGMENT_64(0x19L),
        ROUTINES_64(0x1aL),
        UUID(0x1bL),
        CODE_SIGNATURE(0x1dL),
        SEGMENT_SPLIT_INFO(0x1eL),
        LAZY_LOAD_DYLIB(0x20L),
        ENCRYPTION_INFO(0x21L),
        DYLD_INFO(0x22L),
        VERSION_MIN_MACOSX(0x24L),
        VERSION_MIN_IPHONEOS(0x25L),
        FUNCTION_STARTS(0x26L),
        DYLD_ENVIRONMENT(0x27L),
        DATA_IN_CODE(0x29L),
        SOURCE_VERSION(0x2aL),
        DYLIB_CODE_SIGN_DRS(0x2bL),
        ENCRYPTION_INFO_64(0x2cL),
        LINKER_OPTION(0x2dL),
        LINKER_OPTIMIZATION_HINT(0x2eL),
        VERSION_MIN_TVOS(0x2fL),
        VERSION_MIN_WATCHOS(0x30L),
        BUILD_VERSION(0x32L),
        REQ_DYLD(0x80000000L),
        LOAD_WEAK_DYLIB(0x80000018L),
        RPATH(0x8000001cL),
        REEXPORT_DYLIB(0x8000001fL),
        DYLD_INFO_ONLY(0x80000022L),
        LOAD_UPWARD_DYLIB(0x80000023L),
        MAIN(0x80000028L);

        private final long id;
        LoadCommandType(long id) { this.id = id; }
        public long id() { return id; }
        private static final Map<Long, LoadCommandType> byId = new HashMap<Long, LoadCommandType>(51);
        static {
            for (LoadCommandType e : LoadCommandType.values())
                byId.put(e.id(), e);
        }
        public static LoadCommandType byId(long id) { return byId.get(id); }
    }

    public MachO(KaitaiStream _io) {
        this(_io, null, null);
    }

    public MachO(KaitaiStream _io, KaitaiStruct _parent) {
        this(_io, _parent, null);
    }

    public MachO(KaitaiStream _io, KaitaiStruct _parent, MachO _root) {
        super(_io);
        this._parent = _parent;
        this._root = _root == null ? this : _root;
        _read();
    }
    private void _read() {
        this.magic = MagicType.byId(this._io.readU4be());
        if ( ((magic() == MagicType.FAT_BE) || (magic() == MagicType.FAT_LE)) ) {
            this.fatHeader = new FatHeader(this._io, this, _root);
        }
        if ( ((magic() != MagicType.FAT_BE) && (magic() != MagicType.FAT_LE)) ) {
            this.header = new MachHeader(this._io, this, _root);
        }
        if ( ((magic() != MagicType.FAT_BE) && (magic() != MagicType.FAT_LE)) ) {
            loadCommands = new ArrayList<LoadCommand>(((Number) (header().ncmds())).intValue());
            for (int i = 0; i < header().ncmds(); i++) {
                this.loadCommands.add(new LoadCommand(this._io, this, _root));
            }
        }
    }
    public static class RpathCommand extends KaitaiStruct {
        public static RpathCommand fromFile(String fileName) throws IOException {
            return new RpathCommand(new ByteBufferKaitaiStream(fileName));
        }

        public RpathCommand(KaitaiStream _io) {
            this(_io, null, null);
        }

        public RpathCommand(KaitaiStream _io, MachO.LoadCommand _parent) {
            this(_io, _parent, null);
        }

        public RpathCommand(KaitaiStream _io, MachO.LoadCommand _parent, MachO _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.pathOffset = this._io.readU4le();
            this.path = new String(this._io.readBytesTerm(0, false, true, true), Charset.forName("utf-8"));
        }
        private long pathOffset;
        private String path;
        private MachO _root;
        private MachO.LoadCommand _parent;
        public long pathOffset() { return pathOffset; }
        public String path() { return path; }
        public MachO _root() { return _root; }
        public MachO.LoadCommand _parent() { return _parent; }
    }
    public static class Uleb128 extends KaitaiStruct {
        public static Uleb128 fromFile(String fileName) throws IOException {
            return new Uleb128(new ByteBufferKaitaiStream(fileName));
        }

        public Uleb128(KaitaiStream _io) {
            this(_io, null, null);
        }

        public Uleb128(KaitaiStream _io, KaitaiStruct _parent) {
            this(_io, _parent, null);
        }

        public Uleb128(KaitaiStream _io, KaitaiStruct _parent, MachO _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.b1 = this._io.readU1();
            if ((b1() & 128) != 0) {
                this.b2 = this._io.readU1();
            }
            if ( (((b1() & 128) != 0) && ((b2() & 128) != 0)) ) {
                this.b3 = this._io.readU1();
            }
            if ( (((b1() & 128) != 0) && ((b2() & 128) != 0) && ((b3() & 128) != 0)) ) {
                this.b4 = this._io.readU1();
            }
            if ( (((b1() & 128) != 0) && ((b2() & 128) != 0) && ((b3() & 128) != 0) && ((b4() & 128) != 0)) ) {
                this.b5 = this._io.readU1();
            }
            if ( (((b1() & 128) != 0) && ((b2() & 128) != 0) && ((b3() & 128) != 0) && ((b4() & 128) != 0) && ((b5() & 128) != 0)) ) {
                this.b6 = this._io.readU1();
            }
            if ( (((b1() & 128) != 0) && ((b2() & 128) != 0) && ((b3() & 128) != 0) && ((b4() & 128) != 0) && ((b5() & 128) != 0) && ((b6() & 128) != 0)) ) {
                this.b7 = this._io.readU1();
            }
            if ( (((b1() & 128) != 0) && ((b2() & 128) != 0) && ((b3() & 128) != 0) && ((b4() & 128) != 0) && ((b5() & 128) != 0) && ((b6() & 128) != 0) && ((b7() & 128) != 0)) ) {
                this.b8 = this._io.readU1();
            }
            if ( (((b1() & 128) != 0) && ((b2() & 128) != 0) && ((b3() & 128) != 0) && ((b4() & 128) != 0) && ((b5() & 128) != 0) && ((b6() & 128) != 0) && ((b7() & 128) != 0) && ((b8() & 128) != 0)) ) {
                this.b9 = this._io.readU1();
            }
            if ( (((b1() & 128) != 0) && ((b2() & 128) != 0) && ((b3() & 128) != 0) && ((b4() & 128) != 0) && ((b5() & 128) != 0) && ((b6() & 128) != 0) && ((b7() & 128) != 0) && ((b8() & 128) != 0) && ((b9() & 128) != 0)) ) {
                this.b10 = this._io.readU1();
            }
        }
        private Integer value;
        public Integer value() {
            if (this.value != null)
                return this.value;
            int _tmp = (int) (((KaitaiStream.mod(b1(), 128) << 0) + ((b1() & 128) == 0 ? 0 : ((KaitaiStream.mod(b2(), 128) << 7) + ((b2() & 128) == 0 ? 0 : ((KaitaiStream.mod(b3(), 128) << 14) + ((b3() & 128) == 0 ? 0 : ((KaitaiStream.mod(b4(), 128) << 21) + ((b4() & 128) == 0 ? 0 : ((KaitaiStream.mod(b5(), 128) << 28) + ((b5() & 128) == 0 ? 0 : ((KaitaiStream.mod(b6(), 128) << 35) + ((b6() & 128) == 0 ? 0 : ((KaitaiStream.mod(b7(), 128) << 42) + ((b7() & 128) == 0 ? 0 : ((KaitaiStream.mod(b8(), 128) << 49) + ((b8() & 128) == 0 ? 0 : ((KaitaiStream.mod(b9(), 128) << 56) + ((b8() & 128) == 0 ? 0 : (KaitaiStream.mod(b10(), 128) << 63))))))))))))))))))));
            this.value = _tmp;
            return this.value;
        }
        private int b1;
        private Integer b2;
        private Integer b3;
        private Integer b4;
        private Integer b5;
        private Integer b6;
        private Integer b7;
        private Integer b8;
        private Integer b9;
        private Integer b10;
        private MachO _root;
        private KaitaiStruct _parent;
        public int b1() { return b1; }
        public Integer b2() { return b2; }
        public Integer b3() { return b3; }
        public Integer b4() { return b4; }
        public Integer b5() { return b5; }
        public Integer b6() { return b6; }
        public Integer b7() { return b7; }
        public Integer b8() { return b8; }
        public Integer b9() { return b9; }
        public Integer b10() { return b10; }
        public MachO _root() { return _root; }
        public KaitaiStruct _parent() { return _parent; }
    }
    public static class SourceVersionCommand extends KaitaiStruct {
        public static SourceVersionCommand fromFile(String fileName) throws IOException {
            return new SourceVersionCommand(new ByteBufferKaitaiStream(fileName));
        }

        public SourceVersionCommand(KaitaiStream _io) {
            this(_io, null, null);
        }

        public SourceVersionCommand(KaitaiStream _io, MachO.LoadCommand _parent) {
            this(_io, _parent, null);
        }

        public SourceVersionCommand(KaitaiStream _io, MachO.LoadCommand _parent, MachO _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.version = this._io.readU8le();
        }
        private long version;
        private MachO _root;
        private MachO.LoadCommand _parent;
        public long version() { return version; }
        public MachO _root() { return _root; }
        public MachO.LoadCommand _parent() { return _parent; }
    }
    public static class CsBlob extends KaitaiStruct {
        public static CsBlob fromFile(String fileName) throws IOException {
            return new CsBlob(new ByteBufferKaitaiStream(fileName));
        }

        public enum CsMagic {
            BLOB_WRAPPER(0xfade0b01L),
            REQUIREMENT(0xfade0c00L),
            REQUIREMENTS(0xfade0c01L),
            CODE_DIRECTORY(0xfade0c02L),
            EMBEDDED_SIGNATURE(0xfade0cc0L),
            DETACHED_SIGNATURE(0xfade0cc1L),
            ENTITLEMENT(0xfade7171L);

            private final long id;
            CsMagic(long id) { this.id = id; }
            public long id() { return id; }
            private static final Map<Long, CsMagic> byId = new HashMap<Long, CsMagic>(7);
            static {
                for (CsMagic e : CsMagic.values())
                    byId.put(e.id(), e);
            }
            public static CsMagic byId(long id) { return byId.get(id); }
        }

        public CsBlob(KaitaiStream _io) {
            this(_io, null, null);
        }

        public CsBlob(KaitaiStream _io, KaitaiStruct _parent) {
            this(_io, _parent, null);
        }

        public CsBlob(KaitaiStream _io, KaitaiStruct _parent, MachO _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.magic = CsMagic.byId(this._io.readU4be());
            this.length = this._io.readU4be();
            {
                CsMagic on = magic();
                if (on != null) {
                    switch (magic()) {
                    case REQUIREMENT: {
                        this._raw_body = this._io.readBytes((length() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new Requirement(_io__raw_body, this, _root);
                        break;
                    }
                    case CODE_DIRECTORY: {
                        this._raw_body = this._io.readBytes((length() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new CodeDirectory(_io__raw_body, this, _root);
                        break;
                    }
                    case ENTITLEMENT: {
                        this._raw_body = this._io.readBytes((length() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new Entitlement(_io__raw_body, this, _root);
                        break;
                    }
                    case REQUIREMENTS: {
                        this._raw_body = this._io.readBytes((length() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new Requirements(_io__raw_body, this, _root);
                        break;
                    }
                    case BLOB_WRAPPER: {
                        this._raw_body = this._io.readBytes((length() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new BlobWrapper(_io__raw_body, this, _root);
                        break;
                    }
                    case EMBEDDED_SIGNATURE: {
                        this._raw_body = this._io.readBytes((length() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new SuperBlob(_io__raw_body, this, _root);
                        break;
                    }
                    case DETACHED_SIGNATURE: {
                        this._raw_body = this._io.readBytes((length() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new SuperBlob(_io__raw_body, this, _root);
                        break;
                    }
                    default: {
                        this.body = this._io.readBytes((length() - 8));
                        break;
                    }
                    }
                } else {
                    this.body = this._io.readBytes((length() - 8));
                }
            }
        }
        public static class Entitlement extends KaitaiStruct {
            public static Entitlement fromFile(String fileName) throws IOException {
                return new Entitlement(new ByteBufferKaitaiStream(fileName));
            }

            public Entitlement(KaitaiStream _io) {
                this(_io, null, null);
            }

            public Entitlement(KaitaiStream _io, MachO.CsBlob _parent) {
                this(_io, _parent, null);
            }

            public Entitlement(KaitaiStream _io, MachO.CsBlob _parent, MachO _root) {
                super(_io);
                this._parent = _parent;
                this._root = _root;
                _read();
            }
            private void _read() {
                this.data = this._io.readBytesFull();
            }
            private byte[] data;
            private MachO _root;
            private MachO.CsBlob _parent;
            public byte[] data() { return data; }
            public MachO _root() { return _root; }
            public MachO.CsBlob _parent() { return _parent; }
        }
        public static class CodeDirectory extends KaitaiStruct {
            public static CodeDirectory fromFile(String fileName) throws IOException {
                return new CodeDirectory(new ByteBufferKaitaiStream(fileName));
            }

            public CodeDirectory(KaitaiStream _io) {
                this(_io, null, null);
            }

            public CodeDirectory(KaitaiStream _io, MachO.CsBlob _parent) {
                this(_io, _parent, null);
            }

            public CodeDirectory(KaitaiStream _io, MachO.CsBlob _parent, MachO _root) {
                super(_io);
                this._parent = _parent;
                this._root = _root;
                _read();
            }
            private void _read() {
                this.version = this._io.readU4be();
                this.flags = this._io.readU4be();
                this.hashOffset = this._io.readU4be();
                this.identOffset = this._io.readU4be();
                this.nSpecialSlots = this._io.readU4be();
                this.nCodeSlots = this._io.readU4be();
                this.codeLimit = this._io.readU4be();
                this.hashSize = this._io.readU1();
                this.hashType = this._io.readU1();
                this.spare1 = this._io.readU1();
                this.pageSize = this._io.readU1();
                this.spare2 = this._io.readU4be();
                if (version() >= 131328) {
                    this.scatterOffset = this._io.readU4be();
                }
                if (version() >= 131584) {
                    this.teamIdOffset = this._io.readU4be();
                }
            }
            private String ident;
            public String ident() {
                if (this.ident != null)
                    return this.ident;
                long _pos = this._io.pos();
                this._io.seek((identOffset() - 8));
                this.ident = new String(this._io.readBytesTerm(0, false, true, true), Charset.forName("utf-8"));
                this._io.seek(_pos);
                return this.ident;
            }
            private String teamId;
            public String teamId() {
                if (this.teamId != null)
                    return this.teamId;
                long _pos = this._io.pos();
                this._io.seek((teamIdOffset() - 8));
                this.teamId = new String(this._io.readBytesTerm(0, false, true, true), Charset.forName("utf-8"));
                this._io.seek(_pos);
                return this.teamId;
            }
            private ArrayList<byte[]> hashes;
            public ArrayList<byte[]> hashes() {
                if (this.hashes != null)
                    return this.hashes;
                long _pos = this._io.pos();
                this._io.seek(((hashOffset() - 8) - (hashSize() * nSpecialSlots())));
                hashes = new ArrayList<byte[]>(((Number) ((nSpecialSlots() + nCodeSlots()))).intValue());
                for (int i = 0; i < (nSpecialSlots() + nCodeSlots()); i++) {
                    this.hashes.add(this._io.readBytes(hashSize()));
                }
                this._io.seek(_pos);
                return this.hashes;
            }
            private long version;
            private long flags;
            private long hashOffset;
            private long identOffset;
            private long nSpecialSlots;
            private long nCodeSlots;
            private long codeLimit;
            private int hashSize;
            private int hashType;
            private int spare1;
            private int pageSize;
            private long spare2;
            private Long scatterOffset;
            private Long teamIdOffset;
            private MachO _root;
            private MachO.CsBlob _parent;
            public long version() { return version; }
            public long flags() { return flags; }
            public long hashOffset() { return hashOffset; }
            public long identOffset() { return identOffset; }
            public long nSpecialSlots() { return nSpecialSlots; }
            public long nCodeSlots() { return nCodeSlots; }
            public long codeLimit() { return codeLimit; }
            public int hashSize() { return hashSize; }
            public int hashType() { return hashType; }
            public int spare1() { return spare1; }
            public int pageSize() { return pageSize; }
            public long spare2() { return spare2; }
            public Long scatterOffset() { return scatterOffset; }
            public Long teamIdOffset() { return teamIdOffset; }
            public MachO _root() { return _root; }
            public MachO.CsBlob _parent() { return _parent; }
        }
        public static class Data extends KaitaiStruct {
            public static Data fromFile(String fileName) throws IOException {
                return new Data(new ByteBufferKaitaiStream(fileName));
            }

            public Data(KaitaiStream _io) {
                this(_io, null, null);
            }

            public Data(KaitaiStream _io, KaitaiStruct _parent) {
                this(_io, _parent, null);
            }

            public Data(KaitaiStream _io, KaitaiStruct _parent, MachO _root) {
                super(_io);
                this._parent = _parent;
                this._root = _root;
                _read();
            }
            private void _read() {
                this.length = this._io.readU4be();
                this.value = this._io.readBytes(length());
                this.padding = this._io.readBytes((4 - (length() & 3)));
            }
            private long length;
            private byte[] value;
            private byte[] padding;
            private MachO _root;
            private KaitaiStruct _parent;
            public long length() { return length; }
            public byte[] value() { return value; }
            public byte[] padding() { return padding; }
            public MachO _root() { return _root; }
            public KaitaiStruct _parent() { return _parent; }
        }
        public static class SuperBlob extends KaitaiStruct {
            public static SuperBlob fromFile(String fileName) throws IOException {
                return new SuperBlob(new ByteBufferKaitaiStream(fileName));
            }

            public SuperBlob(KaitaiStream _io) {
                this(_io, null, null);
            }

            public SuperBlob(KaitaiStream _io, MachO.CsBlob _parent) {
                this(_io, _parent, null);
            }

            public SuperBlob(KaitaiStream _io, MachO.CsBlob _parent, MachO _root) {
                super(_io);
                this._parent = _parent;
                this._root = _root;
                _read();
            }
            private void _read() {
                this.count = this._io.readU4be();
                blobs = new ArrayList<BlobIndex>(((Number) (count())).intValue());
                for (int i = 0; i < count(); i++) {
                    this.blobs.add(new BlobIndex(this._io, this, _root));
                }
            }
            private long count;
            private ArrayList<BlobIndex> blobs;
            private MachO _root;
            private MachO.CsBlob _parent;
            public long count() { return count; }
            public ArrayList<BlobIndex> blobs() { return blobs; }
            public MachO _root() { return _root; }
            public MachO.CsBlob _parent() { return _parent; }
        }
        public static class Expr extends KaitaiStruct {
            public static Expr fromFile(String fileName) throws IOException {
                return new Expr(new ByteBufferKaitaiStream(fileName));
            }

            public enum OpEnum {
                FALSE(0x0L),
                TRUE(0x1L),
                IDENT(0x2L),
                APPLE_ANCHOR(0x3L),
                ANCHOR_HASH(0x4L),
                INFO_KEY_VALUE(0x5L),
                AND_OP(0x6L),
                OR_OP(0x7L),
                CD_HASH(0x8L),
                NOT_OP(0x9L),
                INFO_KEY_FIELD(0xaL),
                CERT_FIELD(0xbL),
                TRUSTED_CERT(0xcL),
                TRUSTED_CERTS(0xdL),
                CERT_GENERIC(0xeL),
                APPLE_GENERIC_ANCHOR(0xfL),
                ENTITLEMENT_FIELD(0x10L);

                private final long id;
                OpEnum(long id) { this.id = id; }
                public long id() { return id; }
                private static final Map<Long, OpEnum> byId = new HashMap<Long, OpEnum>(17);
                static {
                    for (OpEnum e : OpEnum.values())
                        byId.put(e.id(), e);
                }
                public static OpEnum byId(long id) { return byId.get(id); }
            }

            public enum CertSlot {
                LEFT_CERT(0x0L),
                ANCHOR_CERT(0xffffffffL);

                private final long id;
                CertSlot(long id) { this.id = id; }
                public long id() { return id; }
                private static final Map<Long, CertSlot> byId = new HashMap<Long, CertSlot>(2);
                static {
                    for (CertSlot e : CertSlot.values())
                        byId.put(e.id(), e);
                }
                public static CertSlot byId(long id) { return byId.get(id); }
            }

            public Expr(KaitaiStream _io) {
                this(_io, null, null);
            }

            public Expr(KaitaiStream _io, KaitaiStruct _parent) {
                this(_io, _parent, null);
            }

            public Expr(KaitaiStream _io, KaitaiStruct _parent, MachO _root) {
                super(_io);
                this._parent = _parent;
                this._root = _root;
                _read();
            }
            private void _read() {
                this.op = OpEnum.byId(this._io.readU4be());
                {
                    OpEnum on = op();
                    if (on != null) {
                        switch (op()) {
                        case IDENT: {
                            this.data = new IdentExpr(this._io, this, _root);
                            break;
                        }
                        case OR_OP: {
                            this.data = new OrExpr(this._io, this, _root);
                            break;
                        }
                        case INFO_KEY_VALUE: {
                            this.data = new Data(this._io, this, _root);
                            break;
                        }
                        case ANCHOR_HASH: {
                            this.data = new AnchorHashExpr(this._io, this, _root);
                            break;
                        }
                        case INFO_KEY_FIELD: {
                            this.data = new InfoKeyFieldExpr(this._io, this, _root);
                            break;
                        }
                        case NOT_OP: {
                            this.data = new Expr(this._io, this, _root);
                            break;
                        }
                        case ENTITLEMENT_FIELD: {
                            this.data = new EntitlementFieldExpr(this._io, this, _root);
                            break;
                        }
                        case TRUSTED_CERT: {
                            this.data = new CertSlotExpr(this._io, this, _root);
                            break;
                        }
                        case AND_OP: {
                            this.data = new AndExpr(this._io, this, _root);
                            break;
                        }
                        case CERT_GENERIC: {
                            this.data = new CertGenericExpr(this._io, this, _root);
                            break;
                        }
                        case CERT_FIELD: {
                            this.data = new CertFieldExpr(this._io, this, _root);
                            break;
                        }
                        case CD_HASH: {
                            this.data = new Data(this._io, this, _root);
                            break;
                        }
                        case APPLE_GENERIC_ANCHOR: {
                            this.data = new AppleGenericAnchorExpr(this._io, this, _root);
                            break;
                        }
                        }
                    }
                }
            }
            public static class InfoKeyFieldExpr extends KaitaiStruct {
                public static InfoKeyFieldExpr fromFile(String fileName) throws IOException {
                    return new InfoKeyFieldExpr(new ByteBufferKaitaiStream(fileName));
                }

                public InfoKeyFieldExpr(KaitaiStream _io) {
                    this(_io, null, null);
                }

                public InfoKeyFieldExpr(KaitaiStream _io, MachO.CsBlob.Expr _parent) {
                    this(_io, _parent, null);
                }

                public InfoKeyFieldExpr(KaitaiStream _io, MachO.CsBlob.Expr _parent, MachO _root) {
                    super(_io);
                    this._parent = _parent;
                    this._root = _root;
                    _read();
                }
                private void _read() {
                    this.data = new Data(this._io, this, _root);
                    this.match = new Match(this._io, this, _root);
                }
                private Data data;
                private Match match;
                private MachO _root;
                private MachO.CsBlob.Expr _parent;
                public Data data() { return data; }
                public Match match() { return match; }
                public MachO _root() { return _root; }
                public MachO.CsBlob.Expr _parent() { return _parent; }
            }
            public static class CertSlotExpr extends KaitaiStruct {
                public static CertSlotExpr fromFile(String fileName) throws IOException {
                    return new CertSlotExpr(new ByteBufferKaitaiStream(fileName));
                }

                public CertSlotExpr(KaitaiStream _io) {
                    this(_io, null, null);
                }

                public CertSlotExpr(KaitaiStream _io, MachO.CsBlob.Expr _parent) {
                    this(_io, _parent, null);
                }

                public CertSlotExpr(KaitaiStream _io, MachO.CsBlob.Expr _parent, MachO _root) {
                    super(_io);
                    this._parent = _parent;
                    this._root = _root;
                    _read();
                }
                private void _read() {
                    this.value = MachO.CsBlob.Expr.CertSlot.byId(this._io.readU4be());
                }
                private CertSlot value;
                private MachO _root;
                private MachO.CsBlob.Expr _parent;
                public CertSlot value() { return value; }
                public MachO _root() { return _root; }
                public MachO.CsBlob.Expr _parent() { return _parent; }
            }
            public static class CertGenericExpr extends KaitaiStruct {
                public static CertGenericExpr fromFile(String fileName) throws IOException {
                    return new CertGenericExpr(new ByteBufferKaitaiStream(fileName));
                }

                public CertGenericExpr(KaitaiStream _io) {
                    this(_io, null, null);
                }

                public CertGenericExpr(KaitaiStream _io, MachO.CsBlob.Expr _parent) {
                    this(_io, _parent, null);
                }

                public CertGenericExpr(KaitaiStream _io, MachO.CsBlob.Expr _parent, MachO _root) {
                    super(_io);
                    this._parent = _parent;
                    this._root = _root;
                    _read();
                }
                private void _read() {
                    this.certSlot = MachO.CsBlob.Expr.CertSlot.byId(this._io.readU4be());
                    this.data = new Data(this._io, this, _root);
                    this.match = new Match(this._io, this, _root);
                }
                private CertSlot certSlot;
                private Data data;
                private Match match;
                private MachO _root;
                private MachO.CsBlob.Expr _parent;
                public CertSlot certSlot() { return certSlot; }
                public Data data() { return data; }
                public Match match() { return match; }
                public MachO _root() { return _root; }
                public MachO.CsBlob.Expr _parent() { return _parent; }
            }
            public static class IdentExpr extends KaitaiStruct {
                public static IdentExpr fromFile(String fileName) throws IOException {
                    return new IdentExpr(new ByteBufferKaitaiStream(fileName));
                }

                public IdentExpr(KaitaiStream _io) {
                    this(_io, null, null);
                }

                public IdentExpr(KaitaiStream _io, MachO.CsBlob.Expr _parent) {
                    this(_io, _parent, null);
                }

                public IdentExpr(KaitaiStream _io, MachO.CsBlob.Expr _parent, MachO _root) {
                    super(_io);
                    this._parent = _parent;
                    this._root = _root;
                    _read();
                }
                private void _read() {
                    this.identifier = new Data(this._io, this, _root);
                }
                private Data identifier;
                private MachO _root;
                private MachO.CsBlob.Expr _parent;
                public Data identifier() { return identifier; }
                public MachO _root() { return _root; }
                public MachO.CsBlob.Expr _parent() { return _parent; }
            }
            public static class CertFieldExpr extends KaitaiStruct {
                public static CertFieldExpr fromFile(String fileName) throws IOException {
                    return new CertFieldExpr(new ByteBufferKaitaiStream(fileName));
                }

                public CertFieldExpr(KaitaiStream _io) {
                    this(_io, null, null);
                }

                public CertFieldExpr(KaitaiStream _io, MachO.CsBlob.Expr _parent) {
                    this(_io, _parent, null);
                }

                public CertFieldExpr(KaitaiStream _io, MachO.CsBlob.Expr _parent, MachO _root) {
                    super(_io);
                    this._parent = _parent;
                    this._root = _root;
                    _read();
                }
                private void _read() {
                    this.certSlot = MachO.CsBlob.Expr.CertSlot.byId(this._io.readU4be());
                    this.data = new Data(this._io, this, _root);
                    this.match = new Match(this._io, this, _root);
                }
                private CertSlot certSlot;
                private Data data;
                private Match match;
                private MachO _root;
                private MachO.CsBlob.Expr _parent;
                public CertSlot certSlot() { return certSlot; }
                public Data data() { return data; }
                public Match match() { return match; }
                public MachO _root() { return _root; }
                public MachO.CsBlob.Expr _parent() { return _parent; }
            }
            public static class AnchorHashExpr extends KaitaiStruct {
                public static AnchorHashExpr fromFile(String fileName) throws IOException {
                    return new AnchorHashExpr(new ByteBufferKaitaiStream(fileName));
                }

                public AnchorHashExpr(KaitaiStream _io) {
                    this(_io, null, null);
                }

                public AnchorHashExpr(KaitaiStream _io, MachO.CsBlob.Expr _parent) {
                    this(_io, _parent, null);
                }

                public AnchorHashExpr(KaitaiStream _io, MachO.CsBlob.Expr _parent, MachO _root) {
                    super(_io);
                    this._parent = _parent;
                    this._root = _root;
                    _read();
                }
                private void _read() {
                    this.certSlot = MachO.CsBlob.Expr.CertSlot.byId(this._io.readU4be());
                    this.data = new Data(this._io, this, _root);
                }
                private CertSlot certSlot;
                private Data data;
                private MachO _root;
                private MachO.CsBlob.Expr _parent;
                public CertSlot certSlot() { return certSlot; }
                public Data data() { return data; }
                public MachO _root() { return _root; }
                public MachO.CsBlob.Expr _parent() { return _parent; }
            }
            public static class AppleGenericAnchorExpr extends KaitaiStruct {
                public static AppleGenericAnchorExpr fromFile(String fileName) throws IOException {
                    return new AppleGenericAnchorExpr(new ByteBufferKaitaiStream(fileName));
                }

                public AppleGenericAnchorExpr(KaitaiStream _io) {
                    this(_io, null, null);
                }

                public AppleGenericAnchorExpr(KaitaiStream _io, MachO.CsBlob.Expr _parent) {
                    this(_io, _parent, null);
                }

                public AppleGenericAnchorExpr(KaitaiStream _io, MachO.CsBlob.Expr _parent, MachO _root) {
                    super(_io);
                    this._parent = _parent;
                    this._root = _root;
                    _read();
                }
                private void _read() {
                }
                private String value;
                public String value() {
                    if (this.value != null)
                        return this.value;
                    this.value = "anchor apple generic";
                    return this.value;
                }
                private MachO _root;
                private MachO.CsBlob.Expr _parent;
                public MachO _root() { return _root; }
                public MachO.CsBlob.Expr _parent() { return _parent; }
            }
            public static class EntitlementFieldExpr extends KaitaiStruct {
                public static EntitlementFieldExpr fromFile(String fileName) throws IOException {
                    return new EntitlementFieldExpr(new ByteBufferKaitaiStream(fileName));
                }

                public EntitlementFieldExpr(KaitaiStream _io) {
                    this(_io, null, null);
                }

                public EntitlementFieldExpr(KaitaiStream _io, MachO.CsBlob.Expr _parent) {
                    this(_io, _parent, null);
                }

                public EntitlementFieldExpr(KaitaiStream _io, MachO.CsBlob.Expr _parent, MachO _root) {
                    super(_io);
                    this._parent = _parent;
                    this._root = _root;
                    _read();
                }
                private void _read() {
                    this.data = new Data(this._io, this, _root);
                    this.match = new Match(this._io, this, _root);
                }
                private Data data;
                private Match match;
                private MachO _root;
                private MachO.CsBlob.Expr _parent;
                public Data data() { return data; }
                public Match match() { return match; }
                public MachO _root() { return _root; }
                public MachO.CsBlob.Expr _parent() { return _parent; }
            }
            public static class AndExpr extends KaitaiStruct {
                public static AndExpr fromFile(String fileName) throws IOException {
                    return new AndExpr(new ByteBufferKaitaiStream(fileName));
                }

                public AndExpr(KaitaiStream _io) {
                    this(_io, null, null);
                }

                public AndExpr(KaitaiStream _io, MachO.CsBlob.Expr _parent) {
                    this(_io, _parent, null);
                }

                public AndExpr(KaitaiStream _io, MachO.CsBlob.Expr _parent, MachO _root) {
                    super(_io);
                    this._parent = _parent;
                    this._root = _root;
                    _read();
                }
                private void _read() {
                    this.left = new Expr(this._io, this, _root);
                    this.right = new Expr(this._io, this, _root);
                }
                private Expr left;
                private Expr right;
                private MachO _root;
                private MachO.CsBlob.Expr _parent;
                public Expr left() { return left; }
                public Expr right() { return right; }
                public MachO _root() { return _root; }
                public MachO.CsBlob.Expr _parent() { return _parent; }
            }
            public static class OrExpr extends KaitaiStruct {
                public static OrExpr fromFile(String fileName) throws IOException {
                    return new OrExpr(new ByteBufferKaitaiStream(fileName));
                }

                public OrExpr(KaitaiStream _io) {
                    this(_io, null, null);
                }

                public OrExpr(KaitaiStream _io, MachO.CsBlob.Expr _parent) {
                    this(_io, _parent, null);
                }

                public OrExpr(KaitaiStream _io, MachO.CsBlob.Expr _parent, MachO _root) {
                    super(_io);
                    this._parent = _parent;
                    this._root = _root;
                    _read();
                }
                private void _read() {
                    this.left = new Expr(this._io, this, _root);
                    this.right = new Expr(this._io, this, _root);
                }
                private Expr left;
                private Expr right;
                private MachO _root;
                private MachO.CsBlob.Expr _parent;
                public Expr left() { return left; }
                public Expr right() { return right; }
                public MachO _root() { return _root; }
                public MachO.CsBlob.Expr _parent() { return _parent; }
            }
            private OpEnum op;
            private KaitaiStruct data;
            private MachO _root;
            private KaitaiStruct _parent;
            public OpEnum op() { return op; }
            public KaitaiStruct data() { return data; }
            public MachO _root() { return _root; }
            public KaitaiStruct _parent() { return _parent; }
        }
        public static class BlobIndex extends KaitaiStruct {
            public static BlobIndex fromFile(String fileName) throws IOException {
                return new BlobIndex(new ByteBufferKaitaiStream(fileName));
            }

            public enum CsslotType {
                CODE_DIRECTORY(0x0L),
                INFO_SLOT(0x1L),
                REQUIREMENTS(0x2L),
                RESOURCE_DIR(0x3L),
                APPLICATION(0x4L),
                ENTITLEMENTS(0x5L),
                ALTERNATE_CODE_DIRECTORIES(0x1000L),
                SIGNATURE_SLOT(0x10000L);

                private final long id;
                CsslotType(long id) { this.id = id; }
                public long id() { return id; }
                private static final Map<Long, CsslotType> byId = new HashMap<Long, CsslotType>(8);
                static {
                    for (CsslotType e : CsslotType.values())
                        byId.put(e.id(), e);
                }
                public static CsslotType byId(long id) { return byId.get(id); }
            }

            public BlobIndex(KaitaiStream _io) {
                this(_io, null, null);
            }

            public BlobIndex(KaitaiStream _io, MachO.CsBlob.SuperBlob _parent) {
                this(_io, _parent, null);
            }

            public BlobIndex(KaitaiStream _io, MachO.CsBlob.SuperBlob _parent, MachO _root) {
                super(_io);
                this._parent = _parent;
                this._root = _root;
                _read();
            }
            private void _read() {
                this.type = CsslotType.byId(this._io.readU4be());
                this.offset = this._io.readU4be();
            }
            private CsBlob blob;
            public CsBlob blob() {
                if (this.blob != null)
                    return this.blob;
                KaitaiStream io = _parent()._io();
                long _pos = io.pos();
                io.seek((offset() - 8));
                this._raw_blob = io.readBytesFull();
                KaitaiStream _io__raw_blob = new ByteBufferKaitaiStream(_raw_blob);
                this.blob = new CsBlob(_io__raw_blob, this, _root);
                io.seek(_pos);
                return this.blob;
            }
            private CsslotType type;
            private long offset;
            private MachO _root;
            private MachO.CsBlob.SuperBlob _parent;
            private byte[] _raw_blob;
            public CsslotType type() { return type; }
            public long offset() { return offset; }
            public MachO _root() { return _root; }
            public MachO.CsBlob.SuperBlob _parent() { return _parent; }
            public byte[] _raw_blob() { return _raw_blob; }
        }
        public static class Match extends KaitaiStruct {
            public static Match fromFile(String fileName) throws IOException {
                return new Match(new ByteBufferKaitaiStream(fileName));
            }

            public enum Op {
                EXISTS(0x0L),
                EQUAL(0x1L),
                CONTAINS(0x2L),
                BEGINS_WITH(0x3L),
                ENDS_WITH(0x4L),
                LESS_THAN(0x5L),
                GREATER_THAN(0x6L),
                LESS_EQUAL(0x7L),
                GREATER_EQUAL(0x8L);

                private final long id;
                Op(long id) { this.id = id; }
                public long id() { return id; }
                private static final Map<Long, Op> byId = new HashMap<Long, Op>(9);
                static {
                    for (Op e : Op.values())
                        byId.put(e.id(), e);
                }
                public static Op byId(long id) { return byId.get(id); }
            }

            public Match(KaitaiStream _io) {
                this(_io, null, null);
            }

            public Match(KaitaiStream _io, KaitaiStruct _parent) {
                this(_io, _parent, null);
            }

            public Match(KaitaiStream _io, KaitaiStruct _parent, MachO _root) {
                super(_io);
                this._parent = _parent;
                this._root = _root;
                _read();
            }
            private void _read() {
                this.matchOp = Op.byId(this._io.readU4be());
                if (matchOp() != Op.EXISTS) {
                    this.data = new Data(this._io, this, _root);
                }
            }
            private Op matchOp;
            private Data data;
            private MachO _root;
            private KaitaiStruct _parent;
            public Op matchOp() { return matchOp; }
            public Data data() { return data; }
            public MachO _root() { return _root; }
            public KaitaiStruct _parent() { return _parent; }
        }
        public static class Requirement extends KaitaiStruct {
            public static Requirement fromFile(String fileName) throws IOException {
                return new Requirement(new ByteBufferKaitaiStream(fileName));
            }

            public Requirement(KaitaiStream _io) {
                this(_io, null, null);
            }

            public Requirement(KaitaiStream _io, MachO.CsBlob _parent) {
                this(_io, _parent, null);
            }

            public Requirement(KaitaiStream _io, MachO.CsBlob _parent, MachO _root) {
                super(_io);
                this._parent = _parent;
                this._root = _root;
                _read();
            }
            private void _read() {
                this.kind = this._io.readU4be();
                this.expr = new Expr(this._io, this, _root);
            }
            private long kind;
            private Expr expr;
            private MachO _root;
            private MachO.CsBlob _parent;
            public long kind() { return kind; }
            public Expr expr() { return expr; }
            public MachO _root() { return _root; }
            public MachO.CsBlob _parent() { return _parent; }
        }
        public static class Requirements extends KaitaiStruct {
            public static Requirements fromFile(String fileName) throws IOException {
                return new Requirements(new ByteBufferKaitaiStream(fileName));
            }

            public Requirements(KaitaiStream _io) {
                this(_io, null, null);
            }

            public Requirements(KaitaiStream _io, MachO.CsBlob _parent) {
                this(_io, _parent, null);
            }

            public Requirements(KaitaiStream _io, MachO.CsBlob _parent, MachO _root) {
                super(_io);
                this._parent = _parent;
                this._root = _root;
                _read();
            }
            private void _read() {
                this.count = this._io.readU4be();
                items = new ArrayList<RequirementsBlobIndex>(((Number) (count())).intValue());
                for (int i = 0; i < count(); i++) {
                    this.items.add(new RequirementsBlobIndex(this._io, this, _root));
                }
            }
            private long count;
            private ArrayList<RequirementsBlobIndex> items;
            private MachO _root;
            private MachO.CsBlob _parent;
            public long count() { return count; }
            public ArrayList<RequirementsBlobIndex> items() { return items; }
            public MachO _root() { return _root; }
            public MachO.CsBlob _parent() { return _parent; }
        }
        public static class BlobWrapper extends KaitaiStruct {
            public static BlobWrapper fromFile(String fileName) throws IOException {
                return new BlobWrapper(new ByteBufferKaitaiStream(fileName));
            }

            public BlobWrapper(KaitaiStream _io) {
                this(_io, null, null);
            }

            public BlobWrapper(KaitaiStream _io, MachO.CsBlob _parent) {
                this(_io, _parent, null);
            }

            public BlobWrapper(KaitaiStream _io, MachO.CsBlob _parent, MachO _root) {
                super(_io);
                this._parent = _parent;
                this._root = _root;
                _read();
            }
            private void _read() {
                this.data = this._io.readBytesFull();
            }
            private byte[] data;
            private MachO _root;
            private MachO.CsBlob _parent;
            public byte[] data() { return data; }
            public MachO _root() { return _root; }
            public MachO.CsBlob _parent() { return _parent; }
        }
        public static class RequirementsBlobIndex extends KaitaiStruct {
            public static RequirementsBlobIndex fromFile(String fileName) throws IOException {
                return new RequirementsBlobIndex(new ByteBufferKaitaiStream(fileName));
            }

            public enum RequirementType {
                HOST(0x1L),
                GUEST(0x2L),
                DESIGNATED(0x3L),
                LIBRARY(0x4L);

                private final long id;
                RequirementType(long id) { this.id = id; }
                public long id() { return id; }
                private static final Map<Long, RequirementType> byId = new HashMap<Long, RequirementType>(4);
                static {
                    for (RequirementType e : RequirementType.values())
                        byId.put(e.id(), e);
                }
                public static RequirementType byId(long id) { return byId.get(id); }
            }

            public RequirementsBlobIndex(KaitaiStream _io) {
                this(_io, null, null);
            }

            public RequirementsBlobIndex(KaitaiStream _io, MachO.CsBlob.Requirements _parent) {
                this(_io, _parent, null);
            }

            public RequirementsBlobIndex(KaitaiStream _io, MachO.CsBlob.Requirements _parent, MachO _root) {
                super(_io);
                this._parent = _parent;
                this._root = _root;
                _read();
            }
            private void _read() {
                this.type = RequirementType.byId(this._io.readU4be());
                this.offset = this._io.readU4be();
            }
            private CsBlob value;
            public CsBlob value() {
                if (this.value != null)
                    return this.value;
                long _pos = this._io.pos();
                this._io.seek((offset() - 8));
                this.value = new CsBlob(this._io, this, _root);
                this._io.seek(_pos);
                return this.value;
            }
            private RequirementType type;
            private long offset;
            private MachO _root;
            private MachO.CsBlob.Requirements _parent;
            public RequirementType type() { return type; }
            public long offset() { return offset; }
            public MachO _root() { return _root; }
            public MachO.CsBlob.Requirements _parent() { return _parent; }
        }
        private CsMagic magic;
        private long length;
        private Object body;
        private MachO _root;
        private KaitaiStruct _parent;
        private byte[] _raw_body;
        public CsMagic magic() { return magic; }
        public long length() { return length; }
        public Object body() { return body; }
        public MachO _root() { return _root; }
        public KaitaiStruct _parent() { return _parent; }
        public byte[] _raw_body() { return _raw_body; }
    }
    public static class BuildVersionCommand extends KaitaiStruct {
        public static BuildVersionCommand fromFile(String fileName) throws IOException {
            return new BuildVersionCommand(new ByteBufferKaitaiStream(fileName));
        }

        public enum BuildPlatform {
            MACOS(0x1L),
            IOS(0x2L),
            TVOS(0x3L),
            WATCHOS(0x4L),
            BRIDGEOS(0x5L);

            private final long id;
            BuildPlatform(long id) { this.id = id; }
            public long id() { return id; }
            private static final Map<Long, BuildPlatform> byId = new HashMap<Long, BuildPlatform>(5);
            static {
                for (BuildPlatform e : BuildPlatform.values())
                    byId.put(e.id(), e);
            }
            public static BuildPlatform byId(long id) { return byId.get(id); }
        }

        public BuildVersionCommand(KaitaiStream _io) {
            this(_io, null, null);
        }

        public BuildVersionCommand(KaitaiStream _io, MachO.LoadCommand _parent) {
            this(_io, _parent, null);
        }

        public BuildVersionCommand(KaitaiStream _io, MachO.LoadCommand _parent, MachO _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.platform = BuildPlatform.byId(this._io.readU4le());
            this.minos = new Version(this._io, this, _root);
            this.sdk = new Version(this._io, this, _root);
            this.ntools = this._io.readU4le();
            buildToolVersions = new ArrayList<BuildToolVersion>(((Number) (ntools())).intValue());
            for (int i = 0; i < ntools(); i++) {
                this.buildToolVersions.add(new BuildToolVersion(this._io, this, _root));
            }
        }
        private BuildPlatform platform;
        private Version minos;
        private Version sdk;
        private long ntools;
        private ArrayList<BuildToolVersion> buildToolVersions;
        private MachO _root;
        private MachO.LoadCommand _parent;
        public BuildPlatform platform() { return platform; }
        public Version minos() { return minos; }
        public Version sdk() { return sdk; }
        public long ntools() { return ntools; }
        public ArrayList<BuildToolVersion> buildToolVersions() { return buildToolVersions; }
        public MachO _root() { return _root; }
        public MachO.LoadCommand _parent() { return _parent; }
    }
    public static class RoutinesCommand extends KaitaiStruct {
        public static RoutinesCommand fromFile(String fileName) throws IOException {
            return new RoutinesCommand(new ByteBufferKaitaiStream(fileName));
        }

        public RoutinesCommand(KaitaiStream _io) {
            this(_io, null, null);
        }

        public RoutinesCommand(KaitaiStream _io, MachO.LoadCommand _parent) {
            this(_io, _parent, null);
        }

        public RoutinesCommand(KaitaiStream _io, MachO.LoadCommand _parent, MachO _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.initAddress = this._io.readU4le();
            this.initModule = this._io.readU4le();
            this.reserved = this._io.readBytes(24);
        }
        private long initAddress;
        private long initModule;
        private byte[] reserved;
        private MachO _root;
        private MachO.LoadCommand _parent;
        public long initAddress() { return initAddress; }
        public long initModule() { return initModule; }
        public byte[] reserved() { return reserved; }
        public MachO _root() { return _root; }
        public MachO.LoadCommand _parent() { return _parent; }
    }
    public static class MachoFlags extends KaitaiStruct {

        public MachoFlags(KaitaiStream _io, long value) {
            this(_io, null, null, value);
        }

        public MachoFlags(KaitaiStream _io, MachO.MachHeader _parent, long value) {
            this(_io, _parent, null, value);
        }

        public MachoFlags(KaitaiStream _io, MachO.MachHeader _parent, MachO _root, long value) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            this.value = value;
            _read();
        }
        private void _read() {
        }
        private Boolean subsectionsViaSymbols;

        /**
         * safe to divide up the sections into sub-sections via symbols for dead code stripping
         */
        public Boolean subsectionsViaSymbols() {
            if (this.subsectionsViaSymbols != null)
                return this.subsectionsViaSymbols;
            boolean _tmp = (boolean) ((value() & 8192) != 0);
            this.subsectionsViaSymbols = _tmp;
            return this.subsectionsViaSymbols;
        }
        private Boolean deadStrippableDylib;
        public Boolean deadStrippableDylib() {
            if (this.deadStrippableDylib != null)
                return this.deadStrippableDylib;
            boolean _tmp = (boolean) ((value() & 4194304) != 0);
            this.deadStrippableDylib = _tmp;
            return this.deadStrippableDylib;
        }
        private Boolean weakDefines;

        /**
         * the final linked image contains external weak symbols
         */
        public Boolean weakDefines() {
            if (this.weakDefines != null)
                return this.weakDefines;
            boolean _tmp = (boolean) ((value() & 32768) != 0);
            this.weakDefines = _tmp;
            return this.weakDefines;
        }
        private Boolean prebound;

        /**
         * the file has its dynamic undefined references prebound.
         */
        public Boolean prebound() {
            if (this.prebound != null)
                return this.prebound;
            boolean _tmp = (boolean) ((value() & 16) != 0);
            this.prebound = _tmp;
            return this.prebound;
        }
        private Boolean allModsBound;

        /**
         * indicates that this binary binds to all two-level namespace modules of its dependent libraries. only used when MH_PREBINDABLE and MH_TWOLEVEL are both set.
         */
        public Boolean allModsBound() {
            if (this.allModsBound != null)
                return this.allModsBound;
            boolean _tmp = (boolean) ((value() & 4096) != 0);
            this.allModsBound = _tmp;
            return this.allModsBound;
        }
        private Boolean hasTlvDescriptors;
        public Boolean hasTlvDescriptors() {
            if (this.hasTlvDescriptors != null)
                return this.hasTlvDescriptors;
            boolean _tmp = (boolean) ((value() & 8388608) != 0);
            this.hasTlvDescriptors = _tmp;
            return this.hasTlvDescriptors;
        }
        private Boolean forceFlat;

        /**
         * the executable is forcing all images to use flat name space bindings
         */
        public Boolean forceFlat() {
            if (this.forceFlat != null)
                return this.forceFlat;
            boolean _tmp = (boolean) ((value() & 256) != 0);
            this.forceFlat = _tmp;
            return this.forceFlat;
        }
        private Boolean rootSafe;

        /**
         * When this bit is set, the binary declares it is safe for use in processes with uid zero
         */
        public Boolean rootSafe() {
            if (this.rootSafe != null)
                return this.rootSafe;
            boolean _tmp = (boolean) ((value() & 262144) != 0);
            this.rootSafe = _tmp;
            return this.rootSafe;
        }
        private Boolean noUndefs;

        /**
         * the object file has no undefined references
         */
        public Boolean noUndefs() {
            if (this.noUndefs != null)
                return this.noUndefs;
            boolean _tmp = (boolean) ((value() & 1) != 0);
            this.noUndefs = _tmp;
            return this.noUndefs;
        }
        private Boolean setuidSafe;

        /**
         * When this bit is set, the binary declares it is safe for use in processes when issetugid() is true
         */
        public Boolean setuidSafe() {
            if (this.setuidSafe != null)
                return this.setuidSafe;
            boolean _tmp = (boolean) ((value() & 524288) != 0);
            this.setuidSafe = _tmp;
            return this.setuidSafe;
        }
        private Boolean noHeapExecution;
        public Boolean noHeapExecution() {
            if (this.noHeapExecution != null)
                return this.noHeapExecution;
            boolean _tmp = (boolean) ((value() & 16777216) != 0);
            this.noHeapExecution = _tmp;
            return this.noHeapExecution;
        }
        private Boolean noReexportedDylibs;

        /**
         * When this bit is set on a dylib, the static linker does not need to examine dependent dylibs to see if any are re-exported
         */
        public Boolean noReexportedDylibs() {
            if (this.noReexportedDylibs != null)
                return this.noReexportedDylibs;
            boolean _tmp = (boolean) ((value() & 1048576) != 0);
            this.noReexportedDylibs = _tmp;
            return this.noReexportedDylibs;
        }
        private Boolean noMultiDefs;

        /**
         * this umbrella guarantees no multiple defintions of symbols in its sub-images so the two-level namespace hints can always be used.
         */
        public Boolean noMultiDefs() {
            if (this.noMultiDefs != null)
                return this.noMultiDefs;
            boolean _tmp = (boolean) ((value() & 512) != 0);
            this.noMultiDefs = _tmp;
            return this.noMultiDefs;
        }
        private Boolean appExtensionSafe;
        public Boolean appExtensionSafe() {
            if (this.appExtensionSafe != null)
                return this.appExtensionSafe;
            boolean _tmp = (boolean) ((value() & 33554432) != 0);
            this.appExtensionSafe = _tmp;
            return this.appExtensionSafe;
        }
        private Boolean prebindable;

        /**
         * the binary is not prebound but can have its prebinding redone. only used when MH_PREBOUND is not set.
         */
        public Boolean prebindable() {
            if (this.prebindable != null)
                return this.prebindable;
            boolean _tmp = (boolean) ((value() & 2048) != 0);
            this.prebindable = _tmp;
            return this.prebindable;
        }
        private Boolean incrLink;

        /**
         * the object file is the output of an incremental link against a base file and can't be link edited again
         */
        public Boolean incrLink() {
            if (this.incrLink != null)
                return this.incrLink;
            boolean _tmp = (boolean) ((value() & 2) != 0);
            this.incrLink = _tmp;
            return this.incrLink;
        }
        private Boolean bindAtLoad;

        /**
         * the object file's undefined references are bound by the dynamic linker when loaded.
         */
        public Boolean bindAtLoad() {
            if (this.bindAtLoad != null)
                return this.bindAtLoad;
            boolean _tmp = (boolean) ((value() & 8) != 0);
            this.bindAtLoad = _tmp;
            return this.bindAtLoad;
        }
        private Boolean canonical;

        /**
         * the binary has been canonicalized via the unprebind operation
         */
        public Boolean canonical() {
            if (this.canonical != null)
                return this.canonical;
            boolean _tmp = (boolean) ((value() & 16384) != 0);
            this.canonical = _tmp;
            return this.canonical;
        }
        private Boolean twoLevel;

        /**
         * the image is using two-level name space bindings
         */
        public Boolean twoLevel() {
            if (this.twoLevel != null)
                return this.twoLevel;
            boolean _tmp = (boolean) ((value() & 128) != 0);
            this.twoLevel = _tmp;
            return this.twoLevel;
        }
        private Boolean splitSegs;

        /**
         * the file has its read-only and read-write segments split
         */
        public Boolean splitSegs() {
            if (this.splitSegs != null)
                return this.splitSegs;
            boolean _tmp = (boolean) ((value() & 32) != 0);
            this.splitSegs = _tmp;
            return this.splitSegs;
        }
        private Boolean lazyInit;

        /**
         * the shared library init routine is to be run lazily via catching memory faults to its writeable segments (obsolete)
         */
        public Boolean lazyInit() {
            if (this.lazyInit != null)
                return this.lazyInit;
            boolean _tmp = (boolean) ((value() & 64) != 0);
            this.lazyInit = _tmp;
            return this.lazyInit;
        }
        private Boolean allowStackExecution;

        /**
         * When this bit is set, all stacks in the task will be given stack execution privilege.  Only used in MH_EXECUTE filetypes.
         */
        public Boolean allowStackExecution() {
            if (this.allowStackExecution != null)
                return this.allowStackExecution;
            boolean _tmp = (boolean) ((value() & 131072) != 0);
            this.allowStackExecution = _tmp;
            return this.allowStackExecution;
        }
        private Boolean bindsToWeak;

        /**
         * the final linked image uses weak symbols
         */
        public Boolean bindsToWeak() {
            if (this.bindsToWeak != null)
                return this.bindsToWeak;
            boolean _tmp = (boolean) ((value() & 65536) != 0);
            this.bindsToWeak = _tmp;
            return this.bindsToWeak;
        }
        private Boolean noFixPrebinding;

        /**
         * do not have dyld notify the prebinding agent about this executable
         */
        public Boolean noFixPrebinding() {
            if (this.noFixPrebinding != null)
                return this.noFixPrebinding;
            boolean _tmp = (boolean) ((value() & 1024) != 0);
            this.noFixPrebinding = _tmp;
            return this.noFixPrebinding;
        }
        private Boolean dyldLink;

        /**
         * the object file is input for the dynamic linker and can't be staticly link edited again
         */
        public Boolean dyldLink() {
            if (this.dyldLink != null)
                return this.dyldLink;
            boolean _tmp = (boolean) ((value() & 4) != 0);
            this.dyldLink = _tmp;
            return this.dyldLink;
        }
        private Boolean pie;

        /**
         * When this bit is set, the OS will load the main executable at a random address. Only used in MH_EXECUTE filetypes.
         */
        public Boolean pie() {
            if (this.pie != null)
                return this.pie;
            boolean _tmp = (boolean) ((value() & 2097152) != 0);
            this.pie = _tmp;
            return this.pie;
        }
        private long value;
        private MachO _root;
        private MachO.MachHeader _parent;
        public long value() { return value; }
        public MachO _root() { return _root; }
        public MachO.MachHeader _parent() { return _parent; }
    }
    public static class FatHeader extends KaitaiStruct {
        public static FatHeader fromFile(String fileName) throws IOException {
            return new FatHeader(new ByteBufferKaitaiStream(fileName));
        }

        public FatHeader(KaitaiStream _io) {
            this(_io, null, null);
        }

        public FatHeader(KaitaiStream _io, MachO _parent) {
            this(_io, _parent, null);
        }

        public FatHeader(KaitaiStream _io, MachO _parent, MachO _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.nfatArch = this._io.readU4be();
            fatArchs = new ArrayList<FatArch>(((Number) (nfatArch())).intValue());
            for (int i = 0; i < nfatArch(); i++) {
                this.fatArchs.add(new FatArch(this._io, this, _root));
            }
        }
        private long nfatArch;
        private ArrayList<FatArch> fatArchs;
        private MachO _root;
        private MachO _parent;
        public long nfatArch() { return nfatArch; }
        public ArrayList<FatArch> fatArchs() { return fatArchs; }
        public MachO _root() { return _root; }
        public MachO _parent() { return _parent; }
    }
    public static class RoutinesCommand64 extends KaitaiStruct {
        public static RoutinesCommand64 fromFile(String fileName) throws IOException {
            return new RoutinesCommand64(new ByteBufferKaitaiStream(fileName));
        }

        public RoutinesCommand64(KaitaiStream _io) {
            this(_io, null, null);
        }

        public RoutinesCommand64(KaitaiStream _io, MachO.LoadCommand _parent) {
            this(_io, _parent, null);
        }

        public RoutinesCommand64(KaitaiStream _io, MachO.LoadCommand _parent, MachO _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.initAddress = this._io.readU8le();
            this.initModule = this._io.readU8le();
            this.reserved = this._io.readBytes(48);
        }
        private long initAddress;
        private long initModule;
        private byte[] reserved;
        private MachO _root;
        private MachO.LoadCommand _parent;
        public long initAddress() { return initAddress; }
        public long initModule() { return initModule; }
        public byte[] reserved() { return reserved; }
        public MachO _root() { return _root; }
        public MachO.LoadCommand _parent() { return _parent; }
    }
    public static class BuildToolVersion extends KaitaiStruct {
        public static BuildToolVersion fromFile(String fileName) throws IOException {
            return new BuildToolVersion(new ByteBufferKaitaiStream(fileName));
        }

        public enum BuildTool {
            CLANG(0x1L),
            SWIFT(0x2L),
            LD(0x3L);

            private final long id;
            BuildTool(long id) { this.id = id; }
            public long id() { return id; }
            private static final Map<Long, BuildTool> byId = new HashMap<Long, BuildTool>(3);
            static {
                for (BuildTool e : BuildTool.values())
                    byId.put(e.id(), e);
            }
            public static BuildTool byId(long id) { return byId.get(id); }
        }

        public BuildToolVersion(KaitaiStream _io) {
            this(_io, null, null);
        }

        public BuildToolVersion(KaitaiStream _io, MachO.BuildVersionCommand _parent) {
            this(_io, _parent, null);
        }

        public BuildToolVersion(KaitaiStream _io, MachO.BuildVersionCommand _parent, MachO _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.tool = BuildTool.byId(this._io.readU4le());
            this.version = new Version(this._io, this, _root);
        }
        private BuildTool tool;
        private Version version;
        private MachO _root;
        private MachO.BuildVersionCommand _parent;
        public BuildTool tool() { return tool; }
        public Version version() { return version; }
        public MachO _root() { return _root; }
        public MachO.BuildVersionCommand _parent() { return _parent; }
    }
    public static class LinkerOptionCommand extends KaitaiStruct {
        public static LinkerOptionCommand fromFile(String fileName) throws IOException {
            return new LinkerOptionCommand(new ByteBufferKaitaiStream(fileName));
        }

        public LinkerOptionCommand(KaitaiStream _io) {
            this(_io, null, null);
        }

        public LinkerOptionCommand(KaitaiStream _io, MachO.LoadCommand _parent) {
            this(_io, _parent, null);
        }

        public LinkerOptionCommand(KaitaiStream _io, MachO.LoadCommand _parent, MachO _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.numStrings = this._io.readU4le();
            strings = new ArrayList<String>(((Number) (numStrings())).intValue());
            for (int i = 0; i < numStrings(); i++) {
                this.strings.add(new String(this._io.readBytesTerm(0, false, true, true), Charset.forName("utf-8")));
            }
        }
        private long numStrings;
        private ArrayList<String> strings;
        private MachO _root;
        private MachO.LoadCommand _parent;
        public long numStrings() { return numStrings; }
        public ArrayList<String> strings() { return strings; }
        public MachO _root() { return _root; }
        public MachO.LoadCommand _parent() { return _parent; }
    }
    public static class SegmentCommand64 extends KaitaiStruct {
        public static SegmentCommand64 fromFile(String fileName) throws IOException {
            return new SegmentCommand64(new ByteBufferKaitaiStream(fileName));
        }

        public SegmentCommand64(KaitaiStream _io) {
            this(_io, null, null);
        }

        public SegmentCommand64(KaitaiStream _io, MachO.LoadCommand _parent) {
            this(_io, _parent, null);
        }

        public SegmentCommand64(KaitaiStream _io, MachO.LoadCommand _parent, MachO _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.segname = new String(KaitaiStream.bytesStripRight(this._io.readBytes(16), (byte) 0), Charset.forName("ascii"));
            this.vmaddr = this._io.readU8le();
            this.vmsize = this._io.readU8le();
            this.fileoff = this._io.readU8le();
            this.filesize = this._io.readU8le();
            this.maxprot = new VmProt(this._io, this, _root);
            this.initprot = new VmProt(this._io, this, _root);
            this.nsects = this._io.readU4le();
            this.flags = this._io.readU4le();
            sections = new ArrayList<Section64>(((Number) (nsects())).intValue());
            for (int i = 0; i < nsects(); i++) {
                this.sections.add(new Section64(this._io, this, _root));
            }
        }
        public static class Section64 extends KaitaiStruct {
            public static Section64 fromFile(String fileName) throws IOException {
                return new Section64(new ByteBufferKaitaiStream(fileName));
            }

            public Section64(KaitaiStream _io) {
                this(_io, null, null);
            }

            public Section64(KaitaiStream _io, MachO.SegmentCommand64 _parent) {
                this(_io, _parent, null);
            }

            public Section64(KaitaiStream _io, MachO.SegmentCommand64 _parent, MachO _root) {
                super(_io);
                this._parent = _parent;
                this._root = _root;
                _read();
            }
            private void _read() {
                this.sectName = new String(KaitaiStream.bytesStripRight(this._io.readBytes(16), (byte) 0), Charset.forName("ascii"));
                this.segName = new String(KaitaiStream.bytesStripRight(this._io.readBytes(16), (byte) 0), Charset.forName("ascii"));
                this.addr = this._io.readU8le();
                this.size = this._io.readU8le();
                this.offset = this._io.readU4le();
                this.align = this._io.readU4le();
                this.reloff = this._io.readU4le();
                this.nreloc = this._io.readU4le();
                this.flags = this._io.readU4le();
                this.reserved1 = this._io.readU4le();
                this.reserved2 = this._io.readU4le();
                this.reserved3 = this._io.readU4le();
            }
            public static class CfStringList extends KaitaiStruct {
                public static CfStringList fromFile(String fileName) throws IOException {
                    return new CfStringList(new ByteBufferKaitaiStream(fileName));
                }

                public CfStringList(KaitaiStream _io) {
                    this(_io, null, null);
                }

                public CfStringList(KaitaiStream _io, MachO.SegmentCommand64.Section64 _parent) {
                    this(_io, _parent, null);
                }

                public CfStringList(KaitaiStream _io, MachO.SegmentCommand64.Section64 _parent, MachO _root) {
                    super(_io);
                    this._parent = _parent;
                    this._root = _root;
                    _read();
                }
                private void _read() {
                    this.items = new ArrayList<CfString>();
                    {
                        int i = 0;
                        while (!this._io.isEof()) {
                            this.items.add(new CfString(this._io, this, _root));
                            i++;
                        }
                    }
                }
                private ArrayList<CfString> items;
                private MachO _root;
                private MachO.SegmentCommand64.Section64 _parent;
                public ArrayList<CfString> items() { return items; }
                public MachO _root() { return _root; }
                public MachO.SegmentCommand64.Section64 _parent() { return _parent; }
            }
            public static class CfString extends KaitaiStruct {
                public static CfString fromFile(String fileName) throws IOException {
                    return new CfString(new ByteBufferKaitaiStream(fileName));
                }

                public CfString(KaitaiStream _io) {
                    this(_io, null, null);
                }

                public CfString(KaitaiStream _io, MachO.SegmentCommand64.Section64.CfStringList _parent) {
                    this(_io, _parent, null);
                }

                public CfString(KaitaiStream _io, MachO.SegmentCommand64.Section64.CfStringList _parent, MachO _root) {
                    super(_io);
                    this._parent = _parent;
                    this._root = _root;
                    _read();
                }
                private void _read() {
                    this.isa = this._io.readU8le();
                    this.info = this._io.readU8le();
                    this.data = this._io.readU8le();
                    this.length = this._io.readU8le();
                }
                private long isa;
                private long info;
                private long data;
                private long length;
                private MachO _root;
                private MachO.SegmentCommand64.Section64.CfStringList _parent;
                public long isa() { return isa; }
                public long info() { return info; }
                public long data() { return data; }
                public long length() { return length; }
                public MachO _root() { return _root; }
                public MachO.SegmentCommand64.Section64.CfStringList _parent() { return _parent; }
            }
            public static class EhFrameItem extends KaitaiStruct {
                public static EhFrameItem fromFile(String fileName) throws IOException {
                    return new EhFrameItem(new ByteBufferKaitaiStream(fileName));
                }

                public EhFrameItem(KaitaiStream _io) {
                    this(_io, null, null);
                }

                public EhFrameItem(KaitaiStream _io, MachO.SegmentCommand64.Section64.EhFrame _parent) {
                    this(_io, _parent, null);
                }

                public EhFrameItem(KaitaiStream _io, MachO.SegmentCommand64.Section64.EhFrame _parent, MachO _root) {
                    super(_io);
                    this._parent = _parent;
                    this._root = _root;
                    _read();
                }
                private void _read() {
                    this.length = this._io.readU4le();
                    if (length() == 4294967295L) {
                        this.length64 = this._io.readU8le();
                    }
                    this.id = this._io.readU4le();
                    if ( ((length() > 0) && (id() == 0)) ) {
                        this._raw_body = this._io.readBytes((length() - 4));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new Cie(_io__raw_body, this, _root);
                    }
                }
                public static class CharChain extends KaitaiStruct {
                    public static CharChain fromFile(String fileName) throws IOException {
                        return new CharChain(new ByteBufferKaitaiStream(fileName));
                    }

                    public CharChain(KaitaiStream _io) {
                        this(_io, null, null);
                    }

                    public CharChain(KaitaiStream _io, KaitaiStruct _parent) {
                        this(_io, _parent, null);
                    }

                    public CharChain(KaitaiStream _io, KaitaiStruct _parent, MachO _root) {
                        super(_io);
                        this._parent = _parent;
                        this._root = _root;
                        _read();
                    }
                    private void _read() {
                        this.chr = this._io.readU1();
                        if (chr() != 0) {
                            this.next = new CharChain(this._io, this, _root);
                        }
                    }
                    private int chr;
                    private CharChain next;
                    private MachO _root;
                    private KaitaiStruct _parent;
                    public int chr() { return chr; }
                    public CharChain next() { return next; }
                    public MachO _root() { return _root; }
                    public KaitaiStruct _parent() { return _parent; }
                }
                public static class Cie extends KaitaiStruct {
                    public static Cie fromFile(String fileName) throws IOException {
                        return new Cie(new ByteBufferKaitaiStream(fileName));
                    }

                    public Cie(KaitaiStream _io) {
                        this(_io, null, null);
                    }

                    public Cie(KaitaiStream _io, MachO.SegmentCommand64.Section64.EhFrameItem _parent) {
                        this(_io, _parent, null);
                    }

                    public Cie(KaitaiStream _io, MachO.SegmentCommand64.Section64.EhFrameItem _parent, MachO _root) {
                        super(_io);
                        this._parent = _parent;
                        this._root = _root;
                        _read();
                    }
                    private void _read() {
                        this.version = this._io.readU1();
                        this.augStr = new CharChain(this._io, this, _root);
                        this.codeAlignmentFactor = new Uleb128(this._io, this, _root);
                        this.dataAlignmentFactor = new Uleb128(this._io, this, _root);
                        this.returnAddressRegister = this._io.readU1();
                        if (augStr().chr() == 122) {
                            this.augmentation = new AugmentationEntry(this._io, this, _root);
                        }
                    }
                    private int version;
                    private CharChain augStr;
                    private Uleb128 codeAlignmentFactor;
                    private Uleb128 dataAlignmentFactor;
                    private int returnAddressRegister;
                    private AugmentationEntry augmentation;
                    private MachO _root;
                    private MachO.SegmentCommand64.Section64.EhFrameItem _parent;
                    public int version() { return version; }
                    public CharChain augStr() { return augStr; }
                    public Uleb128 codeAlignmentFactor() { return codeAlignmentFactor; }
                    public Uleb128 dataAlignmentFactor() { return dataAlignmentFactor; }
                    public int returnAddressRegister() { return returnAddressRegister; }
                    public AugmentationEntry augmentation() { return augmentation; }
                    public MachO _root() { return _root; }
                    public MachO.SegmentCommand64.Section64.EhFrameItem _parent() { return _parent; }
                }
                public static class AugmentationEntry extends KaitaiStruct {
                    public static AugmentationEntry fromFile(String fileName) throws IOException {
                        return new AugmentationEntry(new ByteBufferKaitaiStream(fileName));
                    }

                    public AugmentationEntry(KaitaiStream _io) {
                        this(_io, null, null);
                    }

                    public AugmentationEntry(KaitaiStream _io, MachO.SegmentCommand64.Section64.EhFrameItem.Cie _parent) {
                        this(_io, _parent, null);
                    }

                    public AugmentationEntry(KaitaiStream _io, MachO.SegmentCommand64.Section64.EhFrameItem.Cie _parent, MachO _root) {
                        super(_io);
                        this._parent = _parent;
                        this._root = _root;
                        _read();
                    }
                    private void _read() {
                        this.length = new Uleb128(this._io, this, _root);
                        if (_parent().augStr().next().chr() == 82) {
                            this.fdePointerEncoding = this._io.readU1();
                        }
                    }
                    private Uleb128 length;
                    private Integer fdePointerEncoding;
                    private MachO _root;
                    private MachO.SegmentCommand64.Section64.EhFrameItem.Cie _parent;
                    public Uleb128 length() { return length; }
                    public Integer fdePointerEncoding() { return fdePointerEncoding; }
                    public MachO _root() { return _root; }
                    public MachO.SegmentCommand64.Section64.EhFrameItem.Cie _parent() { return _parent; }
                }
                private long length;
                private Long length64;
                private long id;
                private Cie body;
                private MachO _root;
                private MachO.SegmentCommand64.Section64.EhFrame _parent;
                private byte[] _raw_body;
                public long length() { return length; }
                public Long length64() { return length64; }
                public long id() { return id; }
                public Cie body() { return body; }
                public MachO _root() { return _root; }
                public MachO.SegmentCommand64.Section64.EhFrame _parent() { return _parent; }
                public byte[] _raw_body() { return _raw_body; }
            }
            public static class EhFrame extends KaitaiStruct {
                public static EhFrame fromFile(String fileName) throws IOException {
                    return new EhFrame(new ByteBufferKaitaiStream(fileName));
                }

                public EhFrame(KaitaiStream _io) {
                    this(_io, null, null);
                }

                public EhFrame(KaitaiStream _io, MachO.SegmentCommand64.Section64 _parent) {
                    this(_io, _parent, null);
                }

                public EhFrame(KaitaiStream _io, MachO.SegmentCommand64.Section64 _parent, MachO _root) {
                    super(_io);
                    this._parent = _parent;
                    this._root = _root;
                    _read();
                }
                private void _read() {
                    this.items = new ArrayList<EhFrameItem>();
                    {
                        int i = 0;
                        while (!this._io.isEof()) {
                            this.items.add(new EhFrameItem(this._io, this, _root));
                            i++;
                        }
                    }
                }
                private ArrayList<EhFrameItem> items;
                private MachO _root;
                private MachO.SegmentCommand64.Section64 _parent;
                public ArrayList<EhFrameItem> items() { return items; }
                public MachO _root() { return _root; }
                public MachO.SegmentCommand64.Section64 _parent() { return _parent; }
            }
            public static class PointerList extends KaitaiStruct {
                public static PointerList fromFile(String fileName) throws IOException {
                    return new PointerList(new ByteBufferKaitaiStream(fileName));
                }

                public PointerList(KaitaiStream _io) {
                    this(_io, null, null);
                }

                public PointerList(KaitaiStream _io, MachO.SegmentCommand64.Section64 _parent) {
                    this(_io, _parent, null);
                }

                public PointerList(KaitaiStream _io, MachO.SegmentCommand64.Section64 _parent, MachO _root) {
                    super(_io);
                    this._parent = _parent;
                    this._root = _root;
                    _read();
                }
                private void _read() {
                    this.items = new ArrayList<Long>();
                    {
                        int i = 0;
                        while (!this._io.isEof()) {
                            this.items.add(this._io.readU8le());
                            i++;
                        }
                    }
                }
                private ArrayList<Long> items;
                private MachO _root;
                private MachO.SegmentCommand64.Section64 _parent;
                public ArrayList<Long> items() { return items; }
                public MachO _root() { return _root; }
                public MachO.SegmentCommand64.Section64 _parent() { return _parent; }
            }
            public static class StringList extends KaitaiStruct {
                public static StringList fromFile(String fileName) throws IOException {
                    return new StringList(new ByteBufferKaitaiStream(fileName));
                }

                public StringList(KaitaiStream _io) {
                    this(_io, null, null);
                }

                public StringList(KaitaiStream _io, MachO.SegmentCommand64.Section64 _parent) {
                    this(_io, _parent, null);
                }

                public StringList(KaitaiStream _io, MachO.SegmentCommand64.Section64 _parent, MachO _root) {
                    super(_io);
                    this._parent = _parent;
                    this._root = _root;
                    _read();
                }
                private void _read() {
                    this.strings = new ArrayList<String>();
                    {
                        int i = 0;
                        while (!this._io.isEof()) {
                            this.strings.add(new String(this._io.readBytesTerm(0, false, true, true), Charset.forName("ascii")));
                            i++;
                        }
                    }
                }
                private ArrayList<String> strings;
                private MachO _root;
                private MachO.SegmentCommand64.Section64 _parent;
                public ArrayList<String> strings() { return strings; }
                public MachO _root() { return _root; }
                public MachO.SegmentCommand64.Section64 _parent() { return _parent; }
            }
            private Object data;
            public Object data() {
                if (this.data != null)
                    return this.data;
                KaitaiStream io = _root._io();
                long _pos = io.pos();
                io.seek(offset());
                switch (sectName()) {
                case "__objc_nlclslist": {
                    this._raw_data = io.readBytes(size());
                    KaitaiStream _io__raw_data = new ByteBufferKaitaiStream(_raw_data);
                    this.data = new PointerList(_io__raw_data, this, _root);
                    break;
                }
                case "__objc_methname": {
                    this._raw_data = io.readBytes(size());
                    KaitaiStream _io__raw_data = new ByteBufferKaitaiStream(_raw_data);
                    this.data = new StringList(_io__raw_data, this, _root);
                    break;
                }
                case "__nl_symbol_ptr": {
                    this._raw_data = io.readBytes(size());
                    KaitaiStream _io__raw_data = new ByteBufferKaitaiStream(_raw_data);
                    this.data = new PointerList(_io__raw_data, this, _root);
                    break;
                }
                case "__la_symbol_ptr": {
                    this._raw_data = io.readBytes(size());
                    KaitaiStream _io__raw_data = new ByteBufferKaitaiStream(_raw_data);
                    this.data = new PointerList(_io__raw_data, this, _root);
                    break;
                }
                case "__objc_selrefs": {
                    this._raw_data = io.readBytes(size());
                    KaitaiStream _io__raw_data = new ByteBufferKaitaiStream(_raw_data);
                    this.data = new PointerList(_io__raw_data, this, _root);
                    break;
                }
                case "__cstring": {
                    this._raw_data = io.readBytes(size());
                    KaitaiStream _io__raw_data = new ByteBufferKaitaiStream(_raw_data);
                    this.data = new StringList(_io__raw_data, this, _root);
                    break;
                }
                case "__objc_classlist": {
                    this._raw_data = io.readBytes(size());
                    KaitaiStream _io__raw_data = new ByteBufferKaitaiStream(_raw_data);
                    this.data = new PointerList(_io__raw_data, this, _root);
                    break;
                }
                case "__objc_protolist": {
                    this._raw_data = io.readBytes(size());
                    KaitaiStream _io__raw_data = new ByteBufferKaitaiStream(_raw_data);
                    this.data = new PointerList(_io__raw_data, this, _root);
                    break;
                }
                case "__objc_imageinfo": {
                    this._raw_data = io.readBytes(size());
                    KaitaiStream _io__raw_data = new ByteBufferKaitaiStream(_raw_data);
                    this.data = new PointerList(_io__raw_data, this, _root);
                    break;
                }
                case "__objc_methtype": {
                    this._raw_data = io.readBytes(size());
                    KaitaiStream _io__raw_data = new ByteBufferKaitaiStream(_raw_data);
                    this.data = new StringList(_io__raw_data, this, _root);
                    break;
                }
                case "__cfstring": {
                    this._raw_data = io.readBytes(size());
                    KaitaiStream _io__raw_data = new ByteBufferKaitaiStream(_raw_data);
                    this.data = new CfStringList(_io__raw_data, this, _root);
                    break;
                }
                case "__objc_classrefs": {
                    this._raw_data = io.readBytes(size());
                    KaitaiStream _io__raw_data = new ByteBufferKaitaiStream(_raw_data);
                    this.data = new PointerList(_io__raw_data, this, _root);
                    break;
                }
                case "__objc_protorefs": {
                    this._raw_data = io.readBytes(size());
                    KaitaiStream _io__raw_data = new ByteBufferKaitaiStream(_raw_data);
                    this.data = new PointerList(_io__raw_data, this, _root);
                    break;
                }
                case "__objc_classname": {
                    this._raw_data = io.readBytes(size());
                    KaitaiStream _io__raw_data = new ByteBufferKaitaiStream(_raw_data);
                    this.data = new StringList(_io__raw_data, this, _root);
                    break;
                }
                case "__got": {
                    this._raw_data = io.readBytes(size());
                    KaitaiStream _io__raw_data = new ByteBufferKaitaiStream(_raw_data);
                    this.data = new PointerList(_io__raw_data, this, _root);
                    break;
                }
                case "__eh_frame": {
                    this._raw_data = io.readBytes(size());
                    KaitaiStream _io__raw_data = new ByteBufferKaitaiStream(_raw_data);
                    this.data = new EhFrame(_io__raw_data, this, _root);
                    break;
                }
                case "__objc_superrefs": {
                    this._raw_data = io.readBytes(size());
                    KaitaiStream _io__raw_data = new ByteBufferKaitaiStream(_raw_data);
                    this.data = new PointerList(_io__raw_data, this, _root);
                    break;
                }
                default: {
                    this.data = io.readBytes(size());
                    break;
                }
                }
                io.seek(_pos);
                return this.data;
            }
            private String sectName;
            private String segName;
            private long addr;
            private long size;
            private long offset;
            private long align;
            private long reloff;
            private long nreloc;
            private long flags;
            private long reserved1;
            private long reserved2;
            private long reserved3;
            private MachO _root;
            private MachO.SegmentCommand64 _parent;
            private byte[] _raw_data;
            public String sectName() { return sectName; }
            public String segName() { return segName; }
            public long addr() { return addr; }
            public long size() { return size; }
            public long offset() { return offset; }
            public long align() { return align; }
            public long reloff() { return reloff; }
            public long nreloc() { return nreloc; }
            public long flags() { return flags; }
            public long reserved1() { return reserved1; }
            public long reserved2() { return reserved2; }
            public long reserved3() { return reserved3; }
            public MachO _root() { return _root; }
            public MachO.SegmentCommand64 _parent() { return _parent; }
            public byte[] _raw_data() { return _raw_data; }
        }
        private String segname;
        private long vmaddr;
        private long vmsize;
        private long fileoff;
        private long filesize;
        private VmProt maxprot;
        private VmProt initprot;
        private long nsects;
        private long flags;
        private ArrayList<Section64> sections;
        private MachO _root;
        private MachO.LoadCommand _parent;
        public String segname() { return segname; }
        public long vmaddr() { return vmaddr; }
        public long vmsize() { return vmsize; }
        public long fileoff() { return fileoff; }
        public long filesize() { return filesize; }
        public VmProt maxprot() { return maxprot; }
        public VmProt initprot() { return initprot; }
        public long nsects() { return nsects; }
        public long flags() { return flags; }
        public ArrayList<Section64> sections() { return sections; }
        public MachO _root() { return _root; }
        public MachO.LoadCommand _parent() { return _parent; }
    }
    public static class VmProt extends KaitaiStruct {
        public static VmProt fromFile(String fileName) throws IOException {
            return new VmProt(new ByteBufferKaitaiStream(fileName));
        }

        public VmProt(KaitaiStream _io) {
            this(_io, null, null);
        }

        public VmProt(KaitaiStream _io, KaitaiStruct _parent) {
            this(_io, _parent, null);
        }

        public VmProt(KaitaiStream _io, KaitaiStruct _parent, MachO _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.stripRead = this._io.readBitsInt(1) != 0;
            this.isMask = this._io.readBitsInt(1) != 0;
            this.reserved0 = this._io.readBitsInt(1) != 0;
            this.copy = this._io.readBitsInt(1) != 0;
            this.noChange = this._io.readBitsInt(1) != 0;
            this.execute = this._io.readBitsInt(1) != 0;
            this.write = this._io.readBitsInt(1) != 0;
            this.read = this._io.readBitsInt(1) != 0;
            this.reserved1 = this._io.readBitsInt(24);
        }
        private boolean stripRead;
        private boolean isMask;
        private boolean reserved0;
        private boolean copy;
        private boolean noChange;
        private boolean execute;
        private boolean write;
        private boolean read;
        private long reserved1;
        private MachO _root;
        private KaitaiStruct _parent;

        /**
         * Special marker to support execute-only protection.
         */
        public boolean stripRead() { return stripRead; }

        /**
         * Indicates to use value as a mask against the actual protection bits.
         */
        public boolean isMask() { return isMask; }

        /**
         * Reserved (unused) bit.
         */
        public boolean reserved0() { return reserved0; }

        /**
         * Used when write permission can not be obtained, to mark the entry as COW.
         */
        public boolean copy() { return copy; }

        /**
         * Used only by memory_object_lock_request to indicate no change to page locks.
         */
        public boolean noChange() { return noChange; }

        /**
         * Execute permission.
         */
        public boolean execute() { return execute; }

        /**
         * Write permission.
         */
        public boolean write() { return write; }

        /**
         * Read permission.
         */
        public boolean read() { return read; }

        /**
         * Reserved (unused) bits.
         */
        public long reserved1() { return reserved1; }
        public MachO _root() { return _root; }
        public KaitaiStruct _parent() { return _parent; }
    }
    public static class DysymtabCommand extends KaitaiStruct {
        public static DysymtabCommand fromFile(String fileName) throws IOException {
            return new DysymtabCommand(new ByteBufferKaitaiStream(fileName));
        }

        public DysymtabCommand(KaitaiStream _io) {
            this(_io, null, null);
        }

        public DysymtabCommand(KaitaiStream _io, MachO.LoadCommand _parent) {
            this(_io, _parent, null);
        }

        public DysymtabCommand(KaitaiStream _io, MachO.LoadCommand _parent, MachO _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.iLocalSym = this._io.readU4le();
            this.nLocalSym = this._io.readU4le();
            this.iExtDefSym = this._io.readU4le();
            this.nExtDefSym = this._io.readU4le();
            this.iUndefSym = this._io.readU4le();
            this.nUndefSym = this._io.readU4le();
            this.tocOff = this._io.readU4le();
            this.nToc = this._io.readU4le();
            this.modTabOff = this._io.readU4le();
            this.nModTab = this._io.readU4le();
            this.extRefSymOff = this._io.readU4le();
            this.nExtRefSyms = this._io.readU4le();
            this.indirectSymOff = this._io.readU4le();
            this.nIndirectSyms = this._io.readU4le();
            this.extRelOff = this._io.readU4le();
            this.nExtRel = this._io.readU4le();
            this.locRelOff = this._io.readU4le();
            this.nLocRel = this._io.readU4le();
        }
        private ArrayList<Long> indirectSymbols;
        public ArrayList<Long> indirectSymbols() {
            if (this.indirectSymbols != null)
                return this.indirectSymbols;
            KaitaiStream io = _root._io();
            long _pos = io.pos();
            io.seek(indirectSymOff());
            indirectSymbols = new ArrayList<Long>(((Number) (nIndirectSyms())).intValue());
            for (int i = 0; i < nIndirectSyms(); i++) {
                this.indirectSymbols.add(io.readU4le());
            }
            io.seek(_pos);
            return this.indirectSymbols;
        }
        private long iLocalSym;
        private long nLocalSym;
        private long iExtDefSym;
        private long nExtDefSym;
        private long iUndefSym;
        private long nUndefSym;
        private long tocOff;
        private long nToc;
        private long modTabOff;
        private long nModTab;
        private long extRefSymOff;
        private long nExtRefSyms;
        private long indirectSymOff;
        private long nIndirectSyms;
        private long extRelOff;
        private long nExtRel;
        private long locRelOff;
        private long nLocRel;
        private MachO _root;
        private MachO.LoadCommand _parent;
        public long iLocalSym() { return iLocalSym; }
        public long nLocalSym() { return nLocalSym; }
        public long iExtDefSym() { return iExtDefSym; }
        public long nExtDefSym() { return nExtDefSym; }
        public long iUndefSym() { return iUndefSym; }
        public long nUndefSym() { return nUndefSym; }
        public long tocOff() { return tocOff; }
        public long nToc() { return nToc; }
        public long modTabOff() { return modTabOff; }
        public long nModTab() { return nModTab; }
        public long extRefSymOff() { return extRefSymOff; }
        public long nExtRefSyms() { return nExtRefSyms; }
        public long indirectSymOff() { return indirectSymOff; }
        public long nIndirectSyms() { return nIndirectSyms; }
        public long extRelOff() { return extRelOff; }
        public long nExtRel() { return nExtRel; }
        public long locRelOff() { return locRelOff; }
        public long nLocRel() { return nLocRel; }
        public MachO _root() { return _root; }
        public MachO.LoadCommand _parent() { return _parent; }
    }
    public static class MachHeader extends KaitaiStruct {
        public static MachHeader fromFile(String fileName) throws IOException {
            return new MachHeader(new ByteBufferKaitaiStream(fileName));
        }

        public MachHeader(KaitaiStream _io) {
            this(_io, null, null);
        }

        public MachHeader(KaitaiStream _io, MachO _parent) {
            this(_io, _parent, null);
        }

        public MachHeader(KaitaiStream _io, MachO _parent, MachO _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.cputype = MachO.CpuType.byId(this._io.readU4le());
            this.cpusubtype = this._io.readU4le();
            this.filetype = MachO.FileType.byId(this._io.readU4le());
            this.ncmds = this._io.readU4le();
            this.sizeofcmds = this._io.readU4le();
            this.flags = this._io.readU4le();
            if ( ((_root.magic() == MachO.MagicType.MACHO_BE_X64) || (_root.magic() == MachO.MagicType.MACHO_LE_X64)) ) {
                this.reserved = this._io.readU4le();
            }
        }
        private MachoFlags flagsObj;
        public MachoFlags flagsObj() {
            if (this.flagsObj != null)
                return this.flagsObj;
            this.flagsObj = new MachoFlags(this._io, this, _root, flags());
            return this.flagsObj;
        }
        private CpuType cputype;
        private long cpusubtype;
        private FileType filetype;
        private long ncmds;
        private long sizeofcmds;
        private long flags;
        private Long reserved;
        private MachO _root;
        private MachO _parent;
        public CpuType cputype() { return cputype; }
        public long cpusubtype() { return cpusubtype; }
        public FileType filetype() { return filetype; }
        public long ncmds() { return ncmds; }
        public long sizeofcmds() { return sizeofcmds; }
        public long flags() { return flags; }
        public Long reserved() { return reserved; }
        public MachO _root() { return _root; }
        public MachO _parent() { return _parent; }
    }
    public static class LinkeditDataCommand extends KaitaiStruct {
        public static LinkeditDataCommand fromFile(String fileName) throws IOException {
            return new LinkeditDataCommand(new ByteBufferKaitaiStream(fileName));
        }

        public LinkeditDataCommand(KaitaiStream _io) {
            this(_io, null, null);
        }

        public LinkeditDataCommand(KaitaiStream _io, MachO.LoadCommand _parent) {
            this(_io, _parent, null);
        }

        public LinkeditDataCommand(KaitaiStream _io, MachO.LoadCommand _parent, MachO _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.dataOff = this._io.readU4le();
            this.dataSize = this._io.readU4le();
        }
        private long dataOff;
        private long dataSize;
        private MachO _root;
        private MachO.LoadCommand _parent;
        public long dataOff() { return dataOff; }
        public long dataSize() { return dataSize; }
        public MachO _root() { return _root; }
        public MachO.LoadCommand _parent() { return _parent; }
    }
    public static class SubCommand extends KaitaiStruct {
        public static SubCommand fromFile(String fileName) throws IOException {
            return new SubCommand(new ByteBufferKaitaiStream(fileName));
        }

        public SubCommand(KaitaiStream _io) {
            this(_io, null, null);
        }

        public SubCommand(KaitaiStream _io, MachO.LoadCommand _parent) {
            this(_io, _parent, null);
        }

        public SubCommand(KaitaiStream _io, MachO.LoadCommand _parent, MachO _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.name = new LcStr(this._io, this, _root);
        }
        private LcStr name;
        private MachO _root;
        private MachO.LoadCommand _parent;
        public LcStr name() { return name; }
        public MachO _root() { return _root; }
        public MachO.LoadCommand _parent() { return _parent; }
    }
    public static class TwolevelHintsCommand extends KaitaiStruct {
        public static TwolevelHintsCommand fromFile(String fileName) throws IOException {
            return new TwolevelHintsCommand(new ByteBufferKaitaiStream(fileName));
        }

        public TwolevelHintsCommand(KaitaiStream _io) {
            this(_io, null, null);
        }

        public TwolevelHintsCommand(KaitaiStream _io, MachO.LoadCommand _parent) {
            this(_io, _parent, null);
        }

        public TwolevelHintsCommand(KaitaiStream _io, MachO.LoadCommand _parent, MachO _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.offset = this._io.readU4le();
            this.numHints = this._io.readU4le();
        }
        private long offset;
        private long numHints;
        private MachO _root;
        private MachO.LoadCommand _parent;
        public long offset() { return offset; }
        public long numHints() { return numHints; }
        public MachO _root() { return _root; }
        public MachO.LoadCommand _parent() { return _parent; }
    }
    public static class Version extends KaitaiStruct {
        public static Version fromFile(String fileName) throws IOException {
            return new Version(new ByteBufferKaitaiStream(fileName));
        }

        public Version(KaitaiStream _io) {
            this(_io, null, null);
        }

        public Version(KaitaiStream _io, KaitaiStruct _parent) {
            this(_io, _parent, null);
        }

        public Version(KaitaiStream _io, KaitaiStruct _parent, MachO _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.p1 = this._io.readU1();
            this.minor = this._io.readU1();
            this.major = this._io.readU1();
            this.release = this._io.readU1();
        }
        private int p1;
        private int minor;
        private int major;
        private int release;
        private MachO _root;
        private KaitaiStruct _parent;
        public int p1() { return p1; }
        public int minor() { return minor; }
        public int major() { return major; }
        public int release() { return release; }
        public MachO _root() { return _root; }
        public KaitaiStruct _parent() { return _parent; }
    }
    public static class EncryptionInfoCommand extends KaitaiStruct {
        public static EncryptionInfoCommand fromFile(String fileName) throws IOException {
            return new EncryptionInfoCommand(new ByteBufferKaitaiStream(fileName));
        }

        public EncryptionInfoCommand(KaitaiStream _io) {
            this(_io, null, null);
        }

        public EncryptionInfoCommand(KaitaiStream _io, MachO.LoadCommand _parent) {
            this(_io, _parent, null);
        }

        public EncryptionInfoCommand(KaitaiStream _io, MachO.LoadCommand _parent, MachO _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.cryptoff = this._io.readU4le();
            this.cryptsize = this._io.readU4le();
            this.cryptid = this._io.readU4le();
            if ( ((_root.magic() == MachO.MagicType.MACHO_BE_X64) || (_root.magic() == MachO.MagicType.MACHO_LE_X64)) ) {
                this.pad = this._io.readU4le();
            }
        }
        private long cryptoff;
        private long cryptsize;
        private long cryptid;
        private Long pad;
        private MachO _root;
        private MachO.LoadCommand _parent;
        public long cryptoff() { return cryptoff; }
        public long cryptsize() { return cryptsize; }
        public long cryptid() { return cryptid; }
        public Long pad() { return pad; }
        public MachO _root() { return _root; }
        public MachO.LoadCommand _parent() { return _parent; }
    }
    public static class CodeSignatureCommand extends KaitaiStruct {
        public static CodeSignatureCommand fromFile(String fileName) throws IOException {
            return new CodeSignatureCommand(new ByteBufferKaitaiStream(fileName));
        }

        public CodeSignatureCommand(KaitaiStream _io) {
            this(_io, null, null);
        }

        public CodeSignatureCommand(KaitaiStream _io, MachO.LoadCommand _parent) {
            this(_io, _parent, null);
        }

        public CodeSignatureCommand(KaitaiStream _io, MachO.LoadCommand _parent, MachO _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.dataOff = this._io.readU4le();
            this.dataSize = this._io.readU4le();
        }
        private CsBlob codeSignature;
        public CsBlob codeSignature() {
            if (this.codeSignature != null)
                return this.codeSignature;
            KaitaiStream io = _root._io();
            long _pos = io.pos();
            io.seek(dataOff());
            this._raw_codeSignature = io.readBytes(dataSize());
            KaitaiStream _io__raw_codeSignature = new ByteBufferKaitaiStream(_raw_codeSignature);
            this.codeSignature = new CsBlob(_io__raw_codeSignature, this, _root);
            io.seek(_pos);
            return this.codeSignature;
        }
        private long dataOff;
        private long dataSize;
        private MachO _root;
        private MachO.LoadCommand _parent;
        private byte[] _raw_codeSignature;
        public long dataOff() { return dataOff; }
        public long dataSize() { return dataSize; }
        public MachO _root() { return _root; }
        public MachO.LoadCommand _parent() { return _parent; }
        public byte[] _raw_codeSignature() { return _raw_codeSignature; }
    }
    public static class DyldInfoCommand extends KaitaiStruct {
        public static DyldInfoCommand fromFile(String fileName) throws IOException {
            return new DyldInfoCommand(new ByteBufferKaitaiStream(fileName));
        }

        public enum BindOpcode {
            DONE(0x0L),
            SET_DYLIB_ORDINAL_IMMEDIATE(0x10L),
            SET_DYLIB_ORDINAL_ULEB(0x20L),
            SET_DYLIB_SPECIAL_IMMEDIATE(0x30L),
            SET_SYMBOL_TRAILING_FLAGS_IMMEDIATE(0x40L),
            SET_TYPE_IMMEDIATE(0x50L),
            SET_APPEND_SLEB(0x60L),
            SET_SEGMENT_AND_OFFSET_ULEB(0x70L),
            ADD_ADDRESS_ULEB(0x80L),
            DO_BIND(0x90L),
            DO_BIND_ADD_ADDRESS_ULEB(0xa0L),
            DO_BIND_ADD_ADDRESS_IMMEDIATE_SCALED(0xb0L),
            DO_BIND_ULEB_TIMES_SKIPPING_ULEB(0xc0L);

            private final long id;
            BindOpcode(long id) { this.id = id; }
            public long id() { return id; }
            private static final Map<Long, BindOpcode> byId = new HashMap<Long, BindOpcode>(13);
            static {
                for (BindOpcode e : BindOpcode.values())
                    byId.put(e.id(), e);
            }
            public static BindOpcode byId(long id) { return byId.get(id); }
        }

        public DyldInfoCommand(KaitaiStream _io) {
            this(_io, null, null);
        }

        public DyldInfoCommand(KaitaiStream _io, MachO.LoadCommand _parent) {
            this(_io, _parent, null);
        }

        public DyldInfoCommand(KaitaiStream _io, MachO.LoadCommand _parent, MachO _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.rebaseOff = this._io.readU4le();
            this.rebaseSize = this._io.readU4le();
            this.bindOff = this._io.readU4le();
            this.bindSize = this._io.readU4le();
            this.weakBindOff = this._io.readU4le();
            this.weakBindSize = this._io.readU4le();
            this.lazyBindOff = this._io.readU4le();
            this.lazyBindSize = this._io.readU4le();
            this.exportOff = this._io.readU4le();
            this.exportSize = this._io.readU4le();
        }
        public static class BindItem extends KaitaiStruct {
            public static BindItem fromFile(String fileName) throws IOException {
                return new BindItem(new ByteBufferKaitaiStream(fileName));
            }

            public BindItem(KaitaiStream _io) {
                this(_io, null, null);
            }

            public BindItem(KaitaiStream _io, KaitaiStruct _parent) {
                this(_io, _parent, null);
            }

            public BindItem(KaitaiStream _io, KaitaiStruct _parent, MachO _root) {
                super(_io);
                this._parent = _parent;
                this._root = _root;
                _read();
            }
            private void _read() {
                this.opcodeAndImmediate = this._io.readU1();
                if ( ((opcode() == MachO.DyldInfoCommand.BindOpcode.SET_DYLIB_ORDINAL_ULEB) || (opcode() == MachO.DyldInfoCommand.BindOpcode.SET_APPEND_SLEB) || (opcode() == MachO.DyldInfoCommand.BindOpcode.SET_SEGMENT_AND_OFFSET_ULEB) || (opcode() == MachO.DyldInfoCommand.BindOpcode.ADD_ADDRESS_ULEB) || (opcode() == MachO.DyldInfoCommand.BindOpcode.DO_BIND_ADD_ADDRESS_ULEB) || (opcode() == MachO.DyldInfoCommand.BindOpcode.DO_BIND_ULEB_TIMES_SKIPPING_ULEB)) ) {
                    this.uleb = new Uleb128(this._io, this, _root);
                }
                if (opcode() == MachO.DyldInfoCommand.BindOpcode.DO_BIND_ULEB_TIMES_SKIPPING_ULEB) {
                    this.skip = new Uleb128(this._io, this, _root);
                }
                if (opcode() == MachO.DyldInfoCommand.BindOpcode.SET_SYMBOL_TRAILING_FLAGS_IMMEDIATE) {
                    this.symbol = new String(this._io.readBytesTerm(0, false, true, true), Charset.forName("ascii"));
                }
            }
            private BindOpcode opcode;
            public BindOpcode opcode() {
                if (this.opcode != null)
                    return this.opcode;
                this.opcode = MachO.DyldInfoCommand.BindOpcode.byId((opcodeAndImmediate() & 240));
                return this.opcode;
            }
            private Integer immediate;
            public Integer immediate() {
                if (this.immediate != null)
                    return this.immediate;
                int _tmp = (int) ((opcodeAndImmediate() & 15));
                this.immediate = _tmp;
                return this.immediate;
            }
            private int opcodeAndImmediate;
            private Uleb128 uleb;
            private Uleb128 skip;
            private String symbol;
            private MachO _root;
            private KaitaiStruct _parent;
            public int opcodeAndImmediate() { return opcodeAndImmediate; }
            public Uleb128 uleb() { return uleb; }
            public Uleb128 skip() { return skip; }
            public String symbol() { return symbol; }
            public MachO _root() { return _root; }
            public KaitaiStruct _parent() { return _parent; }
        }
        public static class RebaseData extends KaitaiStruct {
            public static RebaseData fromFile(String fileName) throws IOException {
                return new RebaseData(new ByteBufferKaitaiStream(fileName));
            }

            public enum Opcode {
                DONE(0x0L),
                SET_TYPE_IMMEDIATE(0x10L),
                SET_SEGMENT_AND_OFFSET_ULEB(0x20L),
                ADD_ADDRESS_ULEB(0x30L),
                ADD_ADDRESS_IMMEDIATE_SCALED(0x40L),
                DO_REBASE_IMMEDIATE_TIMES(0x50L),
                DO_REBASE_ULEB_TIMES(0x60L),
                DO_REBASE_ADD_ADDRESS_ULEB(0x70L),
                DO_REBASE_ULEB_TIMES_SKIPPING_ULEB(0x80L);

                private final long id;
                Opcode(long id) { this.id = id; }
                public long id() { return id; }
                private static final Map<Long, Opcode> byId = new HashMap<Long, Opcode>(9);
                static {
                    for (Opcode e : Opcode.values())
                        byId.put(e.id(), e);
                }
                public static Opcode byId(long id) { return byId.get(id); }
            }

            public RebaseData(KaitaiStream _io) {
                this(_io, null, null);
            }

            public RebaseData(KaitaiStream _io, MachO.DyldInfoCommand _parent) {
                this(_io, _parent, null);
            }

            public RebaseData(KaitaiStream _io, MachO.DyldInfoCommand _parent, MachO _root) {
                super(_io);
                this._parent = _parent;
                this._root = _root;
                _read();
            }
            private void _read() {
                this.items = new ArrayList<RebaseItem>();
                {
                    RebaseItem _it;
                    int i = 0;
                    do {
                        _it = new RebaseItem(this._io, this, _root);
                        this.items.add(_it);
                        i++;
                    } while (!(_it.opcode() == Opcode.DONE));
                }
            }
            public static class RebaseItem extends KaitaiStruct {
                public static RebaseItem fromFile(String fileName) throws IOException {
                    return new RebaseItem(new ByteBufferKaitaiStream(fileName));
                }

                public RebaseItem(KaitaiStream _io) {
                    this(_io, null, null);
                }

                public RebaseItem(KaitaiStream _io, MachO.DyldInfoCommand.RebaseData _parent) {
                    this(_io, _parent, null);
                }

                public RebaseItem(KaitaiStream _io, MachO.DyldInfoCommand.RebaseData _parent, MachO _root) {
                    super(_io);
                    this._parent = _parent;
                    this._root = _root;
                    _read();
                }
                private void _read() {
                    this.opcodeAndImmediate = this._io.readU1();
                    if ( ((opcode() == MachO.DyldInfoCommand.RebaseData.Opcode.SET_SEGMENT_AND_OFFSET_ULEB) || (opcode() == MachO.DyldInfoCommand.RebaseData.Opcode.ADD_ADDRESS_ULEB) || (opcode() == MachO.DyldInfoCommand.RebaseData.Opcode.DO_REBASE_ULEB_TIMES) || (opcode() == MachO.DyldInfoCommand.RebaseData.Opcode.DO_REBASE_ADD_ADDRESS_ULEB) || (opcode() == MachO.DyldInfoCommand.RebaseData.Opcode.DO_REBASE_ULEB_TIMES_SKIPPING_ULEB)) ) {
                        this.uleb = new Uleb128(this._io, this, _root);
                    }
                    if (opcode() == MachO.DyldInfoCommand.RebaseData.Opcode.DO_REBASE_ULEB_TIMES_SKIPPING_ULEB) {
                        this.skip = new Uleb128(this._io, this, _root);
                    }
                }
                private Opcode opcode;
                public Opcode opcode() {
                    if (this.opcode != null)
                        return this.opcode;
                    this.opcode = MachO.DyldInfoCommand.RebaseData.Opcode.byId((opcodeAndImmediate() & 240));
                    return this.opcode;
                }
                private Integer immediate;
                public Integer immediate() {
                    if (this.immediate != null)
                        return this.immediate;
                    int _tmp = (int) ((opcodeAndImmediate() & 15));
                    this.immediate = _tmp;
                    return this.immediate;
                }
                private int opcodeAndImmediate;
                private Uleb128 uleb;
                private Uleb128 skip;
                private MachO _root;
                private MachO.DyldInfoCommand.RebaseData _parent;
                public int opcodeAndImmediate() { return opcodeAndImmediate; }
                public Uleb128 uleb() { return uleb; }
                public Uleb128 skip() { return skip; }
                public MachO _root() { return _root; }
                public MachO.DyldInfoCommand.RebaseData _parent() { return _parent; }
            }
            private ArrayList<RebaseItem> items;
            private MachO _root;
            private MachO.DyldInfoCommand _parent;
            public ArrayList<RebaseItem> items() { return items; }
            public MachO _root() { return _root; }
            public MachO.DyldInfoCommand _parent() { return _parent; }
        }
        public static class ExportNode extends KaitaiStruct {
            public static ExportNode fromFile(String fileName) throws IOException {
                return new ExportNode(new ByteBufferKaitaiStream(fileName));
            }

            public ExportNode(KaitaiStream _io) {
                this(_io, null, null);
            }

            public ExportNode(KaitaiStream _io, KaitaiStruct _parent) {
                this(_io, _parent, null);
            }

            public ExportNode(KaitaiStream _io, KaitaiStruct _parent, MachO _root) {
                super(_io);
                this._parent = _parent;
                this._root = _root;
                _read();
            }
            private void _read() {
                this.terminalSize = new Uleb128(this._io, this, _root);
                this.childrenCount = this._io.readU1();
                children = new ArrayList<Child>(((Number) (childrenCount())).intValue());
                for (int i = 0; i < childrenCount(); i++) {
                    this.children.add(new Child(this._io, this, _root));
                }
                this.terminal = this._io.readBytes(terminalSize().value());
            }
            public static class Child extends KaitaiStruct {
                public static Child fromFile(String fileName) throws IOException {
                    return new Child(new ByteBufferKaitaiStream(fileName));
                }

                public Child(KaitaiStream _io) {
                    this(_io, null, null);
                }

                public Child(KaitaiStream _io, MachO.DyldInfoCommand.ExportNode _parent) {
                    this(_io, _parent, null);
                }

                public Child(KaitaiStream _io, MachO.DyldInfoCommand.ExportNode _parent, MachO _root) {
                    super(_io);
                    this._parent = _parent;
                    this._root = _root;
                    _read();
                }
                private void _read() {
                    this.name = new String(this._io.readBytesTerm(0, false, true, true), Charset.forName("ascii"));
                    this.nodeOffset = new Uleb128(this._io, this, _root);
                }
                private ExportNode value;
                public ExportNode value() {
                    if (this.value != null)
                        return this.value;
                    long _pos = this._io.pos();
                    this._io.seek(nodeOffset().value());
                    this.value = new ExportNode(this._io, this, _root);
                    this._io.seek(_pos);
                    return this.value;
                }
                private String name;
                private Uleb128 nodeOffset;
                private MachO _root;
                private MachO.DyldInfoCommand.ExportNode _parent;
                public String name() { return name; }
                public Uleb128 nodeOffset() { return nodeOffset; }
                public MachO _root() { return _root; }
                public MachO.DyldInfoCommand.ExportNode _parent() { return _parent; }
            }
            private Uleb128 terminalSize;
            private int childrenCount;
            private ArrayList<Child> children;
            private byte[] terminal;
            private MachO _root;
            private KaitaiStruct _parent;
            public Uleb128 terminalSize() { return terminalSize; }
            public int childrenCount() { return childrenCount; }
            public ArrayList<Child> children() { return children; }
            public byte[] terminal() { return terminal; }
            public MachO _root() { return _root; }
            public KaitaiStruct _parent() { return _parent; }
        }
        public static class BindData extends KaitaiStruct {
            public static BindData fromFile(String fileName) throws IOException {
                return new BindData(new ByteBufferKaitaiStream(fileName));
            }

            public BindData(KaitaiStream _io) {
                this(_io, null, null);
            }

            public BindData(KaitaiStream _io, MachO.DyldInfoCommand _parent) {
                this(_io, _parent, null);
            }

            public BindData(KaitaiStream _io, MachO.DyldInfoCommand _parent, MachO _root) {
                super(_io);
                this._parent = _parent;
                this._root = _root;
                _read();
            }
            private void _read() {
                this.items = new ArrayList<BindItem>();
                {
                    BindItem _it;
                    int i = 0;
                    do {
                        _it = new BindItem(this._io, this, _root);
                        this.items.add(_it);
                        i++;
                    } while (!(_it.opcode() == MachO.DyldInfoCommand.BindOpcode.DONE));
                }
            }
            private ArrayList<BindItem> items;
            private MachO _root;
            private MachO.DyldInfoCommand _parent;
            public ArrayList<BindItem> items() { return items; }
            public MachO _root() { return _root; }
            public MachO.DyldInfoCommand _parent() { return _parent; }
        }
        public static class LazyBindData extends KaitaiStruct {
            public static LazyBindData fromFile(String fileName) throws IOException {
                return new LazyBindData(new ByteBufferKaitaiStream(fileName));
            }

            public LazyBindData(KaitaiStream _io) {
                this(_io, null, null);
            }

            public LazyBindData(KaitaiStream _io, MachO.DyldInfoCommand _parent) {
                this(_io, _parent, null);
            }

            public LazyBindData(KaitaiStream _io, MachO.DyldInfoCommand _parent, MachO _root) {
                super(_io);
                this._parent = _parent;
                this._root = _root;
                _read();
            }
            private void _read() {
                this.items = new ArrayList<BindItem>();
                {
                    int i = 0;
                    while (!this._io.isEof()) {
                        this.items.add(new BindItem(this._io, this, _root));
                        i++;
                    }
                }
            }
            private ArrayList<BindItem> items;
            private MachO _root;
            private MachO.DyldInfoCommand _parent;
            public ArrayList<BindItem> items() { return items; }
            public MachO _root() { return _root; }
            public MachO.DyldInfoCommand _parent() { return _parent; }
        }
        private RebaseData rebase;
        public RebaseData rebase() {
            if (this.rebase != null)
                return this.rebase;
            KaitaiStream io = _root._io();
            long _pos = io.pos();
            io.seek(rebaseOff());
            this._raw_rebase = io.readBytes(rebaseSize());
            KaitaiStream _io__raw_rebase = new ByteBufferKaitaiStream(_raw_rebase);
            this.rebase = new RebaseData(_io__raw_rebase, this, _root);
            io.seek(_pos);
            return this.rebase;
        }
        private BindData bind;
        public BindData bind() {
            if (this.bind != null)
                return this.bind;
            KaitaiStream io = _root._io();
            long _pos = io.pos();
            io.seek(bindOff());
            this._raw_bind = io.readBytes(bindSize());
            KaitaiStream _io__raw_bind = new ByteBufferKaitaiStream(_raw_bind);
            this.bind = new BindData(_io__raw_bind, this, _root);
            io.seek(_pos);
            return this.bind;
        }
        private LazyBindData lazyBind;
        public LazyBindData lazyBind() {
            if (this.lazyBind != null)
                return this.lazyBind;
            KaitaiStream io = _root._io();
            long _pos = io.pos();
            io.seek(lazyBindOff());
            this._raw_lazyBind = io.readBytes(lazyBindSize());
            KaitaiStream _io__raw_lazyBind = new ByteBufferKaitaiStream(_raw_lazyBind);
            this.lazyBind = new LazyBindData(_io__raw_lazyBind, this, _root);
            io.seek(_pos);
            return this.lazyBind;
        }
        private ExportNode exports;
        public ExportNode exports() {
            if (this.exports != null)
                return this.exports;
            KaitaiStream io = _root._io();
            long _pos = io.pos();
            io.seek(exportOff());
            this._raw_exports = io.readBytes(exportSize());
            KaitaiStream _io__raw_exports = new ByteBufferKaitaiStream(_raw_exports);
            this.exports = new ExportNode(_io__raw_exports, this, _root);
            io.seek(_pos);
            return this.exports;
        }
        private long rebaseOff;
        private long rebaseSize;
        private long bindOff;
        private long bindSize;
        private long weakBindOff;
        private long weakBindSize;
        private long lazyBindOff;
        private long lazyBindSize;
        private long exportOff;
        private long exportSize;
        private MachO _root;
        private MachO.LoadCommand _parent;
        private byte[] _raw_rebase;
        private byte[] _raw_bind;
        private byte[] _raw_lazyBind;
        private byte[] _raw_exports;
        public long rebaseOff() { return rebaseOff; }
        public long rebaseSize() { return rebaseSize; }
        public long bindOff() { return bindOff; }
        public long bindSize() { return bindSize; }
        public long weakBindOff() { return weakBindOff; }
        public long weakBindSize() { return weakBindSize; }
        public long lazyBindOff() { return lazyBindOff; }
        public long lazyBindSize() { return lazyBindSize; }
        public long exportOff() { return exportOff; }
        public long exportSize() { return exportSize; }
        public MachO _root() { return _root; }
        public MachO.LoadCommand _parent() { return _parent; }
        public byte[] _raw_rebase() { return _raw_rebase; }
        public byte[] _raw_bind() { return _raw_bind; }
        public byte[] _raw_lazyBind() { return _raw_lazyBind; }
        public byte[] _raw_exports() { return _raw_exports; }
    }
    public static class DylinkerCommand extends KaitaiStruct {
        public static DylinkerCommand fromFile(String fileName) throws IOException {
            return new DylinkerCommand(new ByteBufferKaitaiStream(fileName));
        }

        public DylinkerCommand(KaitaiStream _io) {
            this(_io, null, null);
        }

        public DylinkerCommand(KaitaiStream _io, MachO.LoadCommand _parent) {
            this(_io, _parent, null);
        }

        public DylinkerCommand(KaitaiStream _io, MachO.LoadCommand _parent, MachO _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.name = new LcStr(this._io, this, _root);
        }
        private LcStr name;
        private MachO _root;
        private MachO.LoadCommand _parent;
        public LcStr name() { return name; }
        public MachO _root() { return _root; }
        public MachO.LoadCommand _parent() { return _parent; }
    }
    public static class FatArch extends KaitaiStruct {
        public static FatArch fromFile(String fileName) throws IOException {
            return new FatArch(new ByteBufferKaitaiStream(fileName));
        }

        public FatArch(KaitaiStream _io) {
            this(_io, null, null);
        }

        public FatArch(KaitaiStream _io, MachO.FatHeader _parent) {
            this(_io, _parent, null);
        }

        public FatArch(KaitaiStream _io, MachO.FatHeader _parent, MachO _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.cputype = MachO.CpuType.byId(this._io.readU4be());
            this.cpusubtype = this._io.readU4be();
            this.offset = this._io.readU4be();
            this.size = this._io.readU4be();
            this.align = this._io.readU4be();
        }
        private CpuType cputype;
        private long cpusubtype;
        private long offset;
        private long size;
        private long align;
        private MachO _root;
        private MachO.FatHeader _parent;
        public CpuType cputype() { return cputype; }
        public long cpusubtype() { return cpusubtype; }
        public long offset() { return offset; }
        public long size() { return size; }
        public long align() { return align; }
        public MachO _root() { return _root; }
        public MachO.FatHeader _parent() { return _parent; }
    }
    public static class DylibCommand extends KaitaiStruct {
        public static DylibCommand fromFile(String fileName) throws IOException {
            return new DylibCommand(new ByteBufferKaitaiStream(fileName));
        }

        public DylibCommand(KaitaiStream _io) {
            this(_io, null, null);
        }

        public DylibCommand(KaitaiStream _io, MachO.LoadCommand _parent) {
            this(_io, _parent, null);
        }

        public DylibCommand(KaitaiStream _io, MachO.LoadCommand _parent, MachO _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.nameOffset = this._io.readU4le();
            this.timestamp = this._io.readU4le();
            this.currentVersion = this._io.readU4le();
            this.compatibilityVersion = this._io.readU4le();
            this.name = new String(this._io.readBytesTerm(0, false, true, true), Charset.forName("utf-8"));
        }
        private long nameOffset;
        private long timestamp;
        private long currentVersion;
        private long compatibilityVersion;
        private String name;
        private MachO _root;
        private MachO.LoadCommand _parent;
        public long nameOffset() { return nameOffset; }
        public long timestamp() { return timestamp; }
        public long currentVersion() { return currentVersion; }
        public long compatibilityVersion() { return compatibilityVersion; }
        public String name() { return name; }
        public MachO _root() { return _root; }
        public MachO.LoadCommand _parent() { return _parent; }
    }
    public static class SegmentCommand extends KaitaiStruct {
        public static SegmentCommand fromFile(String fileName) throws IOException {
            return new SegmentCommand(new ByteBufferKaitaiStream(fileName));
        }

        public SegmentCommand(KaitaiStream _io) {
            this(_io, null, null);
        }

        public SegmentCommand(KaitaiStream _io, MachO.LoadCommand _parent) {
            this(_io, _parent, null);
        }

        public SegmentCommand(KaitaiStream _io, MachO.LoadCommand _parent, MachO _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.segname = new String(KaitaiStream.bytesStripRight(this._io.readBytes(16), (byte) 0), Charset.forName("ascii"));
            this.vmaddr = this._io.readU4le();
            this.vmsize = this._io.readU4le();
            this.fileoff = this._io.readU4le();
            this.filesize = this._io.readU4le();
            this.maxprot = new VmProt(this._io, this, _root);
            this.initprot = new VmProt(this._io, this, _root);
            this.nsects = this._io.readU4le();
            this.flags = this._io.readU4le();
            sections = new ArrayList<Section>(((Number) (nsects())).intValue());
            for (int i = 0; i < nsects(); i++) {
                this.sections.add(new Section(this._io, this, _root));
            }
        }
        public static class Section extends KaitaiStruct {
            public static Section fromFile(String fileName) throws IOException {
                return new Section(new ByteBufferKaitaiStream(fileName));
            }

            public Section(KaitaiStream _io) {
                this(_io, null, null);
            }

            public Section(KaitaiStream _io, MachO.SegmentCommand _parent) {
                this(_io, _parent, null);
            }

            public Section(KaitaiStream _io, MachO.SegmentCommand _parent, MachO _root) {
                super(_io);
                this._parent = _parent;
                this._root = _root;
                _read();
            }
            private void _read() {
                this.sectName = new String(KaitaiStream.bytesStripRight(this._io.readBytes(16), (byte) 0), Charset.forName("ascii"));
                this.segName = new String(KaitaiStream.bytesStripRight(this._io.readBytes(16), (byte) 0), Charset.forName("ascii"));
                this.addr = this._io.readU4le();
                this.size = this._io.readU4le();
                this.offset = this._io.readU4le();
                this.align = this._io.readU4le();
                this.reloff = this._io.readU4le();
                this.nreloc = this._io.readU4le();
                this.flags = this._io.readU4le();
                this.reserved1 = this._io.readU4le();
                this.reserved2 = this._io.readU4le();
            }
            private String sectName;
            private String segName;
            private long addr;
            private long size;
            private long offset;
            private long align;
            private long reloff;
            private long nreloc;
            private long flags;
            private long reserved1;
            private long reserved2;
            private MachO _root;
            private MachO.SegmentCommand _parent;
            public String sectName() { return sectName; }
            public String segName() { return segName; }
            public long addr() { return addr; }
            public long size() { return size; }
            public long offset() { return offset; }
            public long align() { return align; }
            public long reloff() { return reloff; }
            public long nreloc() { return nreloc; }
            public long flags() { return flags; }
            public long reserved1() { return reserved1; }
            public long reserved2() { return reserved2; }
            public MachO _root() { return _root; }
            public MachO.SegmentCommand _parent() { return _parent; }
        }
        private String segname;
        private long vmaddr;
        private long vmsize;
        private long fileoff;
        private long filesize;
        private VmProt maxprot;
        private VmProt initprot;
        private long nsects;
        private long flags;
        private ArrayList<Section> sections;
        private MachO _root;
        private MachO.LoadCommand _parent;
        public String segname() { return segname; }
        public long vmaddr() { return vmaddr; }
        public long vmsize() { return vmsize; }
        public long fileoff() { return fileoff; }
        public long filesize() { return filesize; }
        public VmProt maxprot() { return maxprot; }
        public VmProt initprot() { return initprot; }
        public long nsects() { return nsects; }
        public long flags() { return flags; }
        public ArrayList<Section> sections() { return sections; }
        public MachO _root() { return _root; }
        public MachO.LoadCommand _parent() { return _parent; }
    }
    public static class LcStr extends KaitaiStruct {
        public static LcStr fromFile(String fileName) throws IOException {
            return new LcStr(new ByteBufferKaitaiStream(fileName));
        }

        public LcStr(KaitaiStream _io) {
            this(_io, null, null);
        }

        public LcStr(KaitaiStream _io, KaitaiStruct _parent) {
            this(_io, _parent, null);
        }

        public LcStr(KaitaiStream _io, KaitaiStruct _parent, MachO _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.length = this._io.readU4le();
            this.value = new String(this._io.readBytesTerm(0, false, true, true), Charset.forName("UTF-8"));
        }
        private long length;
        private String value;
        private MachO _root;
        private KaitaiStruct _parent;
        public long length() { return length; }
        public String value() { return value; }
        public MachO _root() { return _root; }
        public KaitaiStruct _parent() { return _parent; }
    }
    public static class LoadCommand extends KaitaiStruct {
        public static LoadCommand fromFile(String fileName) throws IOException {
            return new LoadCommand(new ByteBufferKaitaiStream(fileName));
        }

        public LoadCommand(KaitaiStream _io) {
            this(_io, null, null);
        }

        public LoadCommand(KaitaiStream _io, MachO _parent) {
            this(_io, _parent, null);
        }

        public LoadCommand(KaitaiStream _io, MachO _parent, MachO _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.type = MachO.LoadCommandType.byId(this._io.readU4le());
            this.size = this._io.readU4le();
            {
                LoadCommandType on = type();
                if (on != null) {
                    switch (type()) {
                    case ID_DYLINKER: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new DylinkerCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case REEXPORT_DYLIB: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new DylibCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case BUILD_VERSION: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new BuildVersionCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case SOURCE_VERSION: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new SourceVersionCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case FUNCTION_STARTS: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new LinkeditDataCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case RPATH: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new RpathCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case SUB_FRAMEWORK: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new SubCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case ROUTINES: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new RoutinesCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case SUB_LIBRARY: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new SubCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case DYLD_INFO_ONLY: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new DyldInfoCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case DYLD_ENVIRONMENT: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new DylinkerCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case LOAD_DYLINKER: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new DylinkerCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case SEGMENT_SPLIT_INFO: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new LinkeditDataCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case MAIN: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new EntryPointCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case LOAD_DYLIB: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new DylibCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case ENCRYPTION_INFO: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new EncryptionInfoCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case DYSYMTAB: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new DysymtabCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case TWOLEVEL_HINTS: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new TwolevelHintsCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case ENCRYPTION_INFO_64: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new EncryptionInfoCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case LINKER_OPTION: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new LinkerOptionCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case DYLD_INFO: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new DyldInfoCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case VERSION_MIN_TVOS: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new VersionMinCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case LOAD_UPWARD_DYLIB: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new DylibCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case SEGMENT_64: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new SegmentCommand64(_io__raw_body, this, _root);
                        break;
                    }
                    case SEGMENT: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new SegmentCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case SUB_UMBRELLA: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new SubCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case VERSION_MIN_WATCHOS: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new VersionMinCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case ROUTINES_64: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new RoutinesCommand64(_io__raw_body, this, _root);
                        break;
                    }
                    case ID_DYLIB: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new DylibCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case SUB_CLIENT: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new SubCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case DYLIB_CODE_SIGN_DRS: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new LinkeditDataCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case SYMTAB: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new SymtabCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case LINKER_OPTIMIZATION_HINT: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new LinkeditDataCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case DATA_IN_CODE: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new LinkeditDataCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case CODE_SIGNATURE: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new CodeSignatureCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case VERSION_MIN_IPHONEOS: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new VersionMinCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case LOAD_WEAK_DYLIB: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new DylibCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case LAZY_LOAD_DYLIB: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new DylibCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case UUID: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new UuidCommand(_io__raw_body, this, _root);
                        break;
                    }
                    case VERSION_MIN_MACOSX: {
                        this._raw_body = this._io.readBytes((size() - 8));
                        KaitaiStream _io__raw_body = new ByteBufferKaitaiStream(_raw_body);
                        this.body = new VersionMinCommand(_io__raw_body, this, _root);
                        break;
                    }
                    default: {
                        this.body = this._io.readBytes((size() - 8));
                        break;
                    }
                    }
                } else {
                    this.body = this._io.readBytes((size() - 8));
                }
            }
        }
        private LoadCommandType type;
        private long size;
        private Object body;
        private MachO _root;
        private MachO _parent;
        private byte[] _raw_body;
        public LoadCommandType type() { return type; }
        public long size() { return size; }
        public Object body() { return body; }
        public MachO _root() { return _root; }
        public MachO _parent() { return _parent; }
        public byte[] _raw_body() { return _raw_body; }
    }
    public static class UuidCommand extends KaitaiStruct {
        public static UuidCommand fromFile(String fileName) throws IOException {
            return new UuidCommand(new ByteBufferKaitaiStream(fileName));
        }

        public UuidCommand(KaitaiStream _io) {
            this(_io, null, null);
        }

        public UuidCommand(KaitaiStream _io, MachO.LoadCommand _parent) {
            this(_io, _parent, null);
        }

        public UuidCommand(KaitaiStream _io, MachO.LoadCommand _parent, MachO _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.uuid = this._io.readBytes(16);
        }
        private byte[] uuid;
        private MachO _root;
        private MachO.LoadCommand _parent;
        public byte[] uuid() { return uuid; }
        public MachO _root() { return _root; }
        public MachO.LoadCommand _parent() { return _parent; }
    }
    public static class SymtabCommand extends KaitaiStruct {
        public static SymtabCommand fromFile(String fileName) throws IOException {
            return new SymtabCommand(new ByteBufferKaitaiStream(fileName));
        }

        public SymtabCommand(KaitaiStream _io) {
            this(_io, null, null);
        }

        public SymtabCommand(KaitaiStream _io, MachO.LoadCommand _parent) {
            this(_io, _parent, null);
        }

        public SymtabCommand(KaitaiStream _io, MachO.LoadCommand _parent, MachO _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.symOff = this._io.readU4le();
            this.nSyms = this._io.readU4le();
            this.strOff = this._io.readU4le();
            this.strSize = this._io.readU4le();
        }
        public static class StrTable extends KaitaiStruct {
            public static StrTable fromFile(String fileName) throws IOException {
                return new StrTable(new ByteBufferKaitaiStream(fileName));
            }

            public StrTable(KaitaiStream _io) {
                this(_io, null, null);
            }

            public StrTable(KaitaiStream _io, MachO.SymtabCommand _parent) {
                this(_io, _parent, null);
            }

            public StrTable(KaitaiStream _io, MachO.SymtabCommand _parent, MachO _root) {
                super(_io);
                this._parent = _parent;
                this._root = _root;
                _read();
            }
            private void _read() {
                this.unknown = this._io.readU4le();
                this.items = new ArrayList<String>();
                {
                    String _it;
                    int i = 0;
                    do {
                        _it = new String(this._io.readBytesTerm(0, false, true, true), Charset.forName("ascii"));
                        this.items.add(_it);
                        i++;
                    } while (!(_it.equals("")));
                }
            }
            private long unknown;
            private ArrayList<String> items;
            private MachO _root;
            private MachO.SymtabCommand _parent;
            public long unknown() { return unknown; }
            public ArrayList<String> items() { return items; }
            public MachO _root() { return _root; }
            public MachO.SymtabCommand _parent() { return _parent; }
        }
        public static class Nlist extends KaitaiStruct {
            public static Nlist fromFile(String fileName) throws IOException {
                return new Nlist(new ByteBufferKaitaiStream(fileName));
            }

            public Nlist(KaitaiStream _io) {
                this(_io, null, null);
            }

            public Nlist(KaitaiStream _io, MachO.SymtabCommand _parent) {
                this(_io, _parent, null);
            }

            public Nlist(KaitaiStream _io, MachO.SymtabCommand _parent, MachO _root) {
                super(_io);
                this._parent = _parent;
                this._root = _root;
                _read();
            }
            private void _read() {
                this.un = this._io.readU4le();
                this.type = this._io.readU1();
                this.sect = this._io.readU1();
                this.desc = this._io.readU2le();
                {
                    MagicType on = _root.magic();
                    if (on != null) {
                        switch (_root.magic()) {
                        case MACHO_BE_X64: {
                            this.value = this._io.readU8le();
                            break;
                        }
                        case MACHO_LE_X64: {
                            this.value = this._io.readU8le();
                            break;
                        }
                        case MACHO_BE_X86: {
                            this.value = (long) (this._io.readU4le());
                            break;
                        }
                        case MACHO_LE_X86: {
                            this.value = (long) (this._io.readU4le());
                            break;
                        }
                        }
                    }
                }
            }
            private long un;
            private int type;
            private int sect;
            private int desc;
            private Long value;
            private MachO _root;
            private MachO.SymtabCommand _parent;
            public long un() { return un; }
            public int type() { return type; }
            public int sect() { return sect; }
            public int desc() { return desc; }
            public Long value() { return value; }
            public MachO _root() { return _root; }
            public MachO.SymtabCommand _parent() { return _parent; }
        }
        private ArrayList<Nlist> symbols;
        public ArrayList<Nlist> symbols() {
            if (this.symbols != null)
                return this.symbols;
            KaitaiStream io = _root._io();
            long _pos = io.pos();
            io.seek(symOff());
            symbols = new ArrayList<Nlist>(((Number) (nSyms())).intValue());
            for (int i = 0; i < nSyms(); i++) {
                this.symbols.add(new Nlist(io, this, _root));
            }
            io.seek(_pos);
            return this.symbols;
        }
        private StrTable strs;
        public StrTable strs() {
            if (this.strs != null)
                return this.strs;
            KaitaiStream io = _root._io();
            long _pos = io.pos();
            io.seek(strOff());
            this._raw_strs = io.readBytes(strSize());
            KaitaiStream _io__raw_strs = new ByteBufferKaitaiStream(_raw_strs);
            this.strs = new StrTable(_io__raw_strs, this, _root);
            io.seek(_pos);
            return this.strs;
        }
        private long symOff;
        private long nSyms;
        private long strOff;
        private long strSize;
        private MachO _root;
        private MachO.LoadCommand _parent;
        private byte[] _raw_strs;
        public long symOff() { return symOff; }
        public long nSyms() { return nSyms; }
        public long strOff() { return strOff; }
        public long strSize() { return strSize; }
        public MachO _root() { return _root; }
        public MachO.LoadCommand _parent() { return _parent; }
        public byte[] _raw_strs() { return _raw_strs; }
    }
    public static class VersionMinCommand extends KaitaiStruct {
        public static VersionMinCommand fromFile(String fileName) throws IOException {
            return new VersionMinCommand(new ByteBufferKaitaiStream(fileName));
        }

        public VersionMinCommand(KaitaiStream _io) {
            this(_io, null, null);
        }

        public VersionMinCommand(KaitaiStream _io, MachO.LoadCommand _parent) {
            this(_io, _parent, null);
        }

        public VersionMinCommand(KaitaiStream _io, MachO.LoadCommand _parent, MachO _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.version = new Version(this._io, this, _root);
            this.sdk = new Version(this._io, this, _root);
        }
        private Version version;
        private Version sdk;
        private MachO _root;
        private MachO.LoadCommand _parent;
        public Version version() { return version; }
        public Version sdk() { return sdk; }
        public MachO _root() { return _root; }
        public MachO.LoadCommand _parent() { return _parent; }
    }
    public static class EntryPointCommand extends KaitaiStruct {
        public static EntryPointCommand fromFile(String fileName) throws IOException {
            return new EntryPointCommand(new ByteBufferKaitaiStream(fileName));
        }

        public EntryPointCommand(KaitaiStream _io) {
            this(_io, null, null);
        }

        public EntryPointCommand(KaitaiStream _io, MachO.LoadCommand _parent) {
            this(_io, _parent, null);
        }

        public EntryPointCommand(KaitaiStream _io, MachO.LoadCommand _parent, MachO _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.entryOff = this._io.readU8le();
            this.stackSize = this._io.readU8le();
        }
        private long entryOff;
        private long stackSize;
        private MachO _root;
        private MachO.LoadCommand _parent;
        public long entryOff() { return entryOff; }
        public long stackSize() { return stackSize; }
        public MachO _root() { return _root; }
        public MachO.LoadCommand _parent() { return _parent; }
    }
    private MagicType magic;
    private FatHeader fatHeader;
    private MachHeader header;
    private ArrayList<LoadCommand> loadCommands;
    private MachO _root;
    private KaitaiStruct _parent;
    public MagicType magic() { return magic; }
    public FatHeader fatHeader() { return fatHeader; }
    public MachHeader header() { return header; }
    public ArrayList<LoadCommand> loadCommands() { return loadCommands; }
    public MachO _root() { return _root; }
    public KaitaiStruct _parent() { return _parent; }
}
