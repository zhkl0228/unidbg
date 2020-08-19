package net.fornwall.jelf;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.unwind.Frame;
import com.github.unidbg.unwind.Unwinder;
import com.github.unidbg.utils.Inspector;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.ByteArrayOutputStream;

public class GnuEhFrameHeader {

    private static final Log log = LogFactory.getLog(GnuEhFrameHeader.class);

    private static final int VERSION = 1;
    
    private static final int DW_EH_PE_omit = 0xff; /* GNU. Means no value present. */

    private static final int DW_EH_PE_absptr = 0x00;
    private static final int DW_EH_PE_uleb128 = 0x01;
    private static final int DW_EH_PE_udata2 = 0x02;
    private static final int DW_EH_PE_udata4 = 0x03;
    private static final int DW_EH_PE_udata8 = 0x04;
    private static final int DW_EH_PE_sleb128 = 0x09;
    private static final int DW_EH_PE_sdata2 = 0x0A;
    private static final int DW_EH_PE_sdata4 = 0x0B;
    private static final int DW_EH_PE_sdata8 = 0x0C;

    private static final int DW_EH_PE_pcrel = 0x10;
    private static final int DW_EH_PE_textrel = 0x20;
    private static final int DW_EH_PE_datarel = 0x30;
    private static final int DW_EH_PE_funcrel = 0x40;
    private static final int DW_EH_PE_aligned = 0x50;
    private static final int DW_EH_PE_indirect = 0x80; /* gcc extension */

    private static class TableEntry {
        final long location; // function address
        final long address; // fde address
        TableEntry(long location, long address) {
            this.location = location;
            this.address = address;
        }
        @Override
        public String toString() {
            return "TableEntry{" +
                    "location=0x" + Long.toHexString(location) +
                    ", address=0x" + Long.toHexString(address) +
                    '}';
        }
    }

    private final TableEntry[] entries;

    private TableEntry search(long fun) {
        TableEntry tableEntry = null;
        for (TableEntry entry : entries) {
            if (fun >= entry.location) {
                tableEntry = entry;
            } else {
                break;
            }
        }
        return tableEntry;
    }

    private final ElfParser parser;

    GnuEhFrameHeader(final ElfParser parser, final long offset, int size) {
        super();
        this.parser = parser;
        parser.seek(offset);

        Off off = new Off(offset);
        int version = parser.readUnsignedByte(); off.pos++;
        if (version != VERSION) {
            throw new IllegalStateException("version is: " + version);
        }

        int eh_frame_ptr_enc = parser.readUnsignedByte(); off.pos++;
        int fde_count_enc = parser.readUnsignedByte(); off.pos++;
        int table_enc = parser.readUnsignedByte(); off.pos++;
        long eh_frame_ptr = readEncodedPointer(parser, eh_frame_ptr_enc, off);
        long fde_count = readEncodedPointer(parser, fde_count_enc, off);
        entries = new TableEntry[(int) fde_count];
        for (int i = 0; i < fde_count; i++) {
            long location = readEncodedPointer(parser, table_enc, off);
            long address = readEncodedPointer(parser, table_enc, off);
            entries[i] = new TableEntry(location, address);
            if (log.isDebugEnabled()) {
                log.debug("Table entry: eh_frame_ptr=0x" + Long.toHexString(eh_frame_ptr) + ", location=0x" + Long.toHexString(location) + ", address=0x" + Long.toHexString(address) + ", size=" + size);
            }
        }

        if (off.pos - off.init != size) {
            throw new IllegalStateException("size=" + size + ", pos=" + off.pos);
        }
    }

    private static class Off {
        final long init;
        long pos;
        Off(long init) {
            this.init = init;
            this.pos = init;
        }
    }

    /* read a uleb128 encoded value and advance pointer */
    private static long readULEB128(ElfParser parser, Off off) {
        long result = 0;
        int shift = 0;
        int b;
        do {
            b = parser.readUnsignedByte(); off.pos++;
            result |= (b & 0x7f) << shift;
            shift += 7;
        } while ((b & 0x80) != 0);
        return result;
    }

    /* read a sleb128 encoded value and advance pointer */
    private static long readSLEB128(ElfParser parser, Off off) {
        long result = 0;
        int shift = 0;
        int b;
        do {
            b = parser.readUnsignedByte(); off.pos++;
            result |= (b & 0x7f) << shift;
            shift += 7;
        } while ((b & 0x80) != 0);
        if (((b & 0x40) != 0)) {
            result |= -(1 << shift);
        }
        return result;
    }

    private static long readEncodedPointer(ElfParser parser, int encoding, Off off) {
        if (encoding == DW_EH_PE_omit) {
            return 0;
        }
        long last_pos = off.pos;

        long result;
        /* first get value */
        switch (encoding & 0xf) {
            /*case DW_EH_PE_absptr:
                result = *((uintptr_t*)p);
                p += sizeof(uintptr_t);
                break;*/
            case DW_EH_PE_uleb128:
                result = readULEB128(parser, off);
                break;
            case DW_EH_PE_udata2:
                result = parser.readShort() & 0xffffL; off.pos += 2;
                break;
            case DW_EH_PE_udata4:
                result = parser.readInt() & 0xffffffffL; off.pos += 4;
                break;
            case DW_EH_PE_sdata2:
                result = parser.readShort(); off.pos += 2;
                break;
            case DW_EH_PE_sdata4:
                result = parser.readInt(); off.pos += 4;
                break;
            case DW_EH_PE_udata8:
            case DW_EH_PE_sdata8:
                result = parser.readLong(); off.pos += 8;
                break;
            case DW_EH_PE_sleb128:
            default:
                throw new IllegalStateException("not supported: encoding=0x" + Integer.toHexString(encoding));
        }

        /* then add relative offset */
        switch ( encoding & 0x70 ) {
            case DW_EH_PE_absptr:
                /* do nothing */
                break;
            case DW_EH_PE_pcrel:
                result += last_pos;
                break;
            case DW_EH_PE_datarel:
                result += off.init;
                break;
            case DW_EH_PE_textrel:
            case DW_EH_PE_funcrel:
            case DW_EH_PE_aligned:
            default:
                throw new IllegalStateException("not supported: encoding=0x" + Integer.toHexString(encoding));
        }

        /* then apply indirection */
        if ((encoding & DW_EH_PE_indirect) != 0) {
//            result = *((uintptr_t*)result);
            throw new IllegalStateException("DW_EH_PE_indirect");
        }

        return result;
    }

    public Frame dwarf_step(Emulator<?> emulator, Unwinder unwinder, Module module, long fun, DwarfCursor context) {
        TableEntry entry = search(fun);
        if (entry == null) {
            return null;
        }

        FDE fde = dwarf_get_fde(entry.address);
        if (log.isDebugEnabled()) {
            log.debug("dwarf_step entry=" + entry + ", fun=0x" + Long.toHexString(fun) + ", fde=" + fde);
        }

        return null;
    }

    private static class FDE {
        final CIE cie;
        final long pc_start;
        final long pc_end;
        final byte[] cfa_instructions;
        FDE(CIE cie, long pc_start, long pc_end, byte[] cfa_instructions) {
            this.cie = cie;
            this.pc_start = pc_start;
            this.pc_end = pc_end;
            this.cfa_instructions = cfa_instructions;
        }
    }

    private FDE dwarf_get_fde(long fde_offset) {
        Off off = new Off(fde_offset);
        parser.seek(fde_offset);
        int length = parser.readInt(); off.pos += 4;
        if (length == -1) {
            throw new UnsupportedOperationException("64bits DWARF FDE");
        }
        long cur_field_offset = off.pos;
        int cie_pointer = parser.readInt(); off.pos += 4;
        if (cie_pointer == 0) {
            throw new IllegalStateException("Invalid cie_pointer");
        }
        long cie_offset = cur_field_offset - cie_pointer;
        CIE cie = dwarf_get_cie(cie_offset);
        parser.seek(off.pos);
        long pc_start = readEncodedPointer(parser, cie.fde_address_encoding, off);
        long adjust = off.pos; // PC Range is always an absolute value
        long pc_range = readEncodedPointer(parser, cie.fde_address_encoding, off) - adjust;
        long pc_end = pc_start + pc_range;
        if (cie.augmentation_string.charAt(0) == 'z') {
            long v64 = readULEB128(parser, off);
            for (long i = 0; i < v64; i++) {
                parser.readUnsignedByte(); off.pos++;
            }
        }
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (long i = off.pos - fde_offset - 4; i < length; i++) {
            baos.write(parser.readUnsignedByte());
        }
        byte[] cfa_instructions = baos.toByteArray();
        if (log.isDebugEnabled()) {
            log.debug(Inspector.inspectString(cfa_instructions, "dwarf_get_fde length=0x" + Integer.toHexString(length) + ", cie_offset=0x" + Long.toHexString(cie_offset) +
                    ", pc_start=0x" + Long.toHexString(pc_start) + ", pc_end=0x" + Long.toHexString(pc_end)));
        }

        return new FDE(cie, pc_start, pc_end, cfa_instructions);
    }

    private static class CIE {
        final int fde_address_encoding;
        final String augmentation_string;
        final long code_alignment_factor;
        final long data_alignment_factor;
        final int return_address_register;
        final byte[] cfa_instructions;
        CIE(int fde_address_encoding, String augmentation_string, long code_alignment_factor, long data_alignment_factor, int return_address_register, byte[] cfa_instructions) {
            this.fde_address_encoding = fde_address_encoding;
            this.augmentation_string = augmentation_string;
            this.code_alignment_factor = code_alignment_factor;
            this.data_alignment_factor = data_alignment_factor;
            this.return_address_register = return_address_register;
            this.cfa_instructions = cfa_instructions;
        }
    }

    private CIE dwarf_get_cie(long cie_offset) {
        parser.seek(cie_offset);
        Off off = new Off(cie_offset);

        int length = parser.readInt(); off.pos += 4;
        if (length == -1) {
            throw new UnsupportedOperationException("64bits DWARF FDE");
        }
        int fde_address_encoding = DW_EH_PE_sdata4;
        int cie_id = parser.readInt(); off.pos += 4;
        if (cie_id != 0) {
            throw new IllegalStateException("Invalid CIE");
        }
        int cie_version = parser.readUnsignedByte(); off.pos++;
        if (cie_version != 1) {
            throw new IllegalStateException("Invalid CIE version: " + cie_version);
        }

        // get augmentation string
        ByteArrayOutputStream baos = new ByteArrayOutputStream(10);
        for (int i = 0; i < 8; i++) {
            int b = parser.readUnsignedByte(); off.pos++;
            if (b == 0) {
                break;
            } else {
                baos.write(b);
            }
        }
        if (baos.size() == 0) {
            throw new IllegalStateException("Invalie CIE augmentation string");
        }
        String augmentation_string = baos.toString();

        long code_alignment_factor = readULEB128(parser, off);
        long data_alignment_factor = readSLEB128(parser, off);
        int return_address_register = parser.readUnsignedByte(); off.pos++;
        long cfa_instructions_offset;
        if ('z' != augmentation_string.charAt(0)) {
            cfa_instructions_offset = off.pos;
        } else {
            long v64 = readULEB128(parser, off);
            cfa_instructions_offset = off.pos + v64;
            char[] as = augmentation_string.toCharArray();
            for (int i = 1; i < as.length; i++) {
                switch (as[i]) {
                    case 'R': {
                        fde_address_encoding = parser.readUnsignedByte(); off.pos++;
                        break;
                    }
                    case 'L':
                    case 'P':
                    default:
                        throw new UnsupportedOperationException("augmentation_string=" + augmentation_string);
                }
            }
        }
        baos.reset();
        for (long i = cfa_instructions_offset - cie_offset - 4; i < length; i++) {
            baos.write(parser.readUnsignedByte());
        }
        byte[] cfa_instructions = baos.toByteArray();
        if (log.isDebugEnabled()) {
            log.debug(Inspector.inspectString(cfa_instructions, "dwarf_get_cie length=0x" + Integer.toHexString(length) + ", augmentation_string=" + augmentation_string +
                    ", code_alignment_factor=" + code_alignment_factor + ", data_alignment_factor=" + data_alignment_factor + ", return_address_register=" + return_address_register +
                    ", fde_address_encoding=0x" + Integer.toHexString(fde_address_encoding) + ", cfa_instructions_offset=0x" + Long.toHexString(cfa_instructions_offset)));
        }
        return new CIE(fde_address_encoding, augmentation_string, code_alignment_factor, data_alignment_factor, return_address_register, cfa_instructions);
    }

}
