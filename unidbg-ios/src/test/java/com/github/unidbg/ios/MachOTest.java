package com.github.unidbg.ios;

import com.github.unidbg.utils.Inspector;
import com.github.zhkl0228.demumble.DemanglerFactory;
import io.kaitai.MachO;
import io.kaitai.struct.ByteBufferKaitaiStream;
import junit.framework.TestCase;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.StandardOpenOption;
import java.util.List;

public class MachOTest extends TestCase {

    public void testFat() throws Exception {
        FileChannel channel = FileChannel.open(new File("src/test/resources/example_binaries/libsubstrate.dylib").toPath(), StandardOpenOption.READ);
        ByteBuffer buffer = channel.map(FileChannel.MapMode.READ_ONLY, 0, channel.size());

        MachO fat = new MachO(new ByteBufferKaitaiStream(buffer));
        assertEquals(MachO.MagicType.FAT_BE, fat.magic());
        assertNull(fat.header());
        assertNotNull(fat.fatHeader());
        assertNull(fat.loadCommands());

        for (MachO.FatArch arch : fat.fatHeader().fatArchs()) {
            buffer.limit((int) (arch.offset() + arch.size()));
            buffer.position((int) arch.offset());
            ByteBuffer sub = buffer.slice();
            MachO machO = new MachO(new ByteBufferKaitaiStream(sub));
            System.out.println("checkMachO cpuType=" + arch.cputype() + ", cpuSubType=" + arch.cpusubtype());
            checkMachO(sub, machO, arch.cputype());
        }

        channel.close();
    }

    public void testMMCommo() throws Exception {
        FileChannel channel = FileChannel.open(new File("src/test/resources/example_binaries/MMCommon").toPath(), StandardOpenOption.READ);
        ByteBuffer buffer = channel.map(FileChannel.MapMode.READ_ONLY, 0, channel.size());

        MachO fat = new MachO(new ByteBufferKaitaiStream(buffer));
        assertEquals(MachO.MagicType.FAT_BE, fat.magic());
        assertNull(fat.header());
        assertNotNull(fat.fatHeader());
        assertNull(fat.loadCommands());

        for (MachO.FatArch arch : fat.fatHeader().fatArchs()) {
            buffer.limit((int) (arch.offset() + arch.size()));
            buffer.position((int) arch.offset());
            ByteBuffer sub = buffer.slice();
            MachO machO = new MachO(new ByteBufferKaitaiStream(sub));
            System.out.println("checkMachO cpuType=" + arch.cputype() + ", cpuSubType=" + arch.cpusubtype());
            checkMachO(sub, machO, arch.cputype());
        }

        channel.close();
    }

    public void testFileFormat() throws Exception {
        FileChannel channel = FileChannel.open(new File("src/test/resources/example_binaries/libsubstrate_arm64.dylib").toPath(), StandardOpenOption.READ);
        ByteBuffer buffer = channel.map(FileChannel.MapMode.READ_ONLY, 0, channel.size());

        MachO machO = new MachO(new ByteBufferKaitaiStream(buffer));
        checkMachO(buffer, machO, MachO.CpuType.ARM64);

        channel.close();
    }

    private void checkMachO(ByteBuffer buffer, MachO machO, MachO.CpuType cpuType) {
        assertNotNull(machO);
        assertNull(machO.fatHeader());

        assertEquals(cpuType == MachO.CpuType.ARM64 ? MachO.MagicType.MACHO_LE_X64 : MachO.MagicType.MACHO_LE_X86, machO.magic());

        MachO.MachHeader header = machO.header();
        assertNotNull(header);
        assertEquals(cpuType, header.cputype());
        assertEquals(MachO.FileType.DYLIB, header.filetype());

        List<MachO.LoadCommand> commands = machO.loadCommands();
        assertNotNull(commands);
        assertFalse(commands.isEmpty());

        for (MachO.LoadCommand command : commands) {
            switch (command.type()) {
                case UUID:
                    assertEquals(24, command.size());
                    MachO.UuidCommand uuidCommand = (MachO.UuidCommand) command.body();
                    Inspector.inspect(uuidCommand.uuid(), "uuid");
                    break;
                case SOURCE_VERSION:
                    MachO.SourceVersionCommand sourceVersionCommand = (MachO.SourceVersionCommand) command.body();
                    System.out.println("sourceVersion=0x" + Long.toHexString(sourceVersionCommand.version()));
                    break;
                case VERSION_MIN_IPHONEOS:
                    MachO.VersionMinCommand versionMinCommand = (MachO.VersionMinCommand) command.body();
                    System.out.println("version=" + versionMinCommand.version().major() + '.' + versionMinCommand.version().minor() + '.' + versionMinCommand.version().release());
                    System.out.println("sdk=" + versionMinCommand.sdk().major() + '.' + versionMinCommand.sdk().minor() + '.' + versionMinCommand.sdk().release());
                    break;
                case CODE_SIGNATURE:
                    MachO.CodeSignatureCommand codeSignatureCommand = (MachO.CodeSignatureCommand) command.body();
                    buffer.position((int) codeSignatureCommand.dataOff());
                    byte[] data = new byte[(int) codeSignatureCommand.dataSize()];
                    buffer.get(data);
                    Inspector.inspect(data, "codeSignature offset=" + codeSignatureCommand.dataOff() + ", size=" + codeSignatureCommand.dataSize());
                    break;
                case LOAD_DYLIB:
                case ID_DYLIB:
                case REEXPORT_DYLIB:
                    MachO.DylibCommand dylibCommand = (MachO.DylibCommand) command.body();
                    System.out.println("dylibCommand name=" + dylibCommand.name() + ", nameOffset=" + dylibCommand.nameOffset() + ", timestamp=" + dylibCommand.timestamp() + ", currentVersion=" + dylibCommand.currentVersion() + ", compatibilityVersion=" + dylibCommand.compatibilityVersion() + ", type=" + command.type());
                    break;
                case FUNCTION_STARTS:
                case DYLIB_CODE_SIGN_DRS:
                case DATA_IN_CODE:
                    MachO.LinkeditDataCommand linkEditDataCommand = (MachO.LinkeditDataCommand) command.body();
                    buffer.position((int) linkEditDataCommand.dataOff());
                    data = new byte[(int) linkEditDataCommand.dataSize()];
                    buffer.get(data);
                    Inspector.inspect(data, "linkEditDataCommand type=" + command.type());
                    break;
                case DYLD_INFO:
                case DYLD_INFO_ONLY:
                    MachO.DyldInfoCommand dyldInfoCommand = (MachO.DyldInfoCommand) command.body();
                    System.out.println("dyldInfoCommand rebaseOff=" + dyldInfoCommand.rebaseOff() + ", rebaseSize=" + dyldInfoCommand.rebaseSize() + ", bindOff=" + dyldInfoCommand.bindOff() + ", bindSize=" + dyldInfoCommand.bindSize() + ", weakBindOff=" + dyldInfoCommand.weakBindOff() + ", weakBindSize=" + dyldInfoCommand.weakBindSize() + ", lazyBindOff=" + dyldInfoCommand.lazyBindOff() + ", lazyBindSize=" + dyldInfoCommand.lazyBindSize() + ", exportOff=" + dyldInfoCommand.exportOff() + ", exportSize=" + dyldInfoCommand.exportSize());
                    break;
                case SEGMENT_64:
                    MachO.SegmentCommand64 segmentCommand64 = (MachO.SegmentCommand64) command.body();
                    System.out.println("segmentCommand64 segname=" + segmentCommand64.segname() + ", vmaddr=0x" + Long.toHexString(segmentCommand64.vmaddr()) + ", vmsize=" + segmentCommand64.vmsize() + ", fileoff=0x" + Long.toHexString(segmentCommand64.fileoff()) + ", filesize=" + segmentCommand64.filesize() + ", maxprot=" + segmentCommand64.maxprot() + ", initprot=" + segmentCommand64.initprot());
                    break;
                case SEGMENT:
                    MachO.SegmentCommand segmentCommand = (MachO.SegmentCommand) command.body();
                    System.out.println("segmentCommand segname=" + segmentCommand.segname() + ", vmaddr=0x" + Long.toHexString(segmentCommand.vmaddr()) + ", vmsize=" + segmentCommand.vmsize() + ", fileoff=0x" + Long.toHexString(segmentCommand.fileoff()) + ", filesize=" + segmentCommand.filesize() + ", maxprot=" + segmentCommand.maxprot() + ", initprot=" + segmentCommand.initprot());
                    break;
                case SYMTAB:
                    MachO.SymtabCommand symtabCommand = (MachO.SymtabCommand) command.body();
                    System.out.println("symtabCommand symOff=" + symtabCommand.symOff() + ", nSyms=" + symtabCommand.nSyms() + ", strOff=" + symtabCommand.strOff() + ", strSize=" + symtabCommand.strSize());
                    break;
                case DYSYMTAB:
                    MachO.DysymtabCommand dysymtabCommand = (MachO.DysymtabCommand) command.body();
                    System.out.println("dysymtabCommand nIndirectSyms=" + dysymtabCommand.nIndirectSyms());
                    break;
                case RPATH:
                    MachO.RpathCommand rpathCommand = (MachO.RpathCommand) command.body();
                    System.out.println("rpathCommand path=" + rpathCommand.path() + ", pathOffset=" + rpathCommand.pathOffset());
                    break;
                case ENCRYPTION_INFO:
                case ENCRYPTION_INFO_64:
                    MachO.EncryptionInfoCommand encryptionInfoCommand = (MachO.EncryptionInfoCommand) command.body();
                    System.out.println(command.type() + " cryptoff=" + encryptionInfoCommand.cryptoff() + ", cryptsize=" + encryptionInfoCommand.cryptsize() + ", cryptid=" + encryptionInfoCommand.cryptid());
                    break;
                default:
                    System.err.println("commandType=" + command.type());
                    break;
            }
        }
    }

    public void testDemangler() {
        System.out.println(DemanglerFactory.createDemangler().demangle("__ZNSt3__114__thread_proxyINS_5tupleIJNS_10unique_ptrINS_15__thread_structENS_14default_deleteIS3_EEEEMN6hilive5media18EditorVideoHandlerEFvRKNS_3mapIjNS8_5TrackENS_4lessIjEENS_9allocatorINS_4pairIKjSB_EEEEEEEPS9_SJ_EEEEEPvSQ_"));
    }

}
