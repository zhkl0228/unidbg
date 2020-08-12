package net.fornwall.jelf;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.unwind.Frame;
import com.github.unidbg.unwind.Unwinder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

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

    private final long offset;
    private long pos;

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

    GnuEhFrameHeader(final ElfParser parser, long offset, int size) {
        super();
        parser.seek(offset);
        this.offset = offset;

        int version = parser.readUnsignedByte(); pos++;
        if (version != VERSION) {
            throw new IllegalStateException("version is: " + version);
        }

        int eh_frame_ptr_enc = parser.readUnsignedByte(); pos++;
        int fde_count_enc = parser.readUnsignedByte(); pos++;
        int table_enc = parser.readUnsignedByte(); pos++;
        long eh_frame_ptr = readEncodedPointer(parser, eh_frame_ptr_enc);
        long fde_count = readEncodedPointer(parser, fde_count_enc);
        entries = new TableEntry[(int) fde_count];
        for (int i = 0; i < fde_count; i++) {
            long location = readEncodedPointer(parser, table_enc);
            long address = readEncodedPointer(parser, table_enc);
            entries[i] = new TableEntry(location, address);
            if (log.isDebugEnabled()) {
                log.debug("Table entry: eh_frame_ptr=0x" + Long.toHexString(eh_frame_ptr) + ", location=0x" + Long.toHexString(location) + ", address=0x" + Long.toHexString(address) + ", size=" + size + ", pos=" + pos);
            }
        }

        if (pos != size) {
            throw new IllegalStateException("size=" + size + ", pos=" + pos);
        }
    }

    /* read a uleb128 encoded value and advance pointer */
    private long readULEB128(ElfParser parser) {
        long result = 0;
        int shift = 0;
        int b;
        do {
            b = parser.readUnsignedByte(); pos++;
            result |= (b & 0x7f) << shift;
            shift += 7;
        } while ((b & 0x80) != 0);
        return result;
    }

    private long readEncodedPointer(ElfParser parser, int encoding) {
        if (encoding == DW_EH_PE_omit) {
            return 0;
        }
        long last_pos = pos;

        long result;
        /* first get value */
        switch (encoding & 0xf) {
            /*case DW_EH_PE_absptr:
                result = *((uintptr_t*)p);
                p += sizeof(uintptr_t);
                break;*/
            case DW_EH_PE_uleb128:
                result = readULEB128(parser);
                break;
            case DW_EH_PE_udata2:
                result = parser.readShort() & 0xffffL; pos += 2;
                break;
            case DW_EH_PE_udata4:
                result = parser.readInt() & 0xffffffffL; pos += 4;
                break;
            case DW_EH_PE_sdata2:
                result = parser.readShort(); pos += 2;
                break;
            case DW_EH_PE_sdata4:
                result = parser.readInt(); pos += 4;
                break;
            case DW_EH_PE_udata8:
            case DW_EH_PE_sdata8:
                result = parser.readLong(); pos += 8;
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
                result += (last_pos + offset);
                break;
            case DW_EH_PE_datarel:
                result += offset;
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
        if (log.isDebugEnabled()) {
            log.debug("dwarf_step entry=" + entry + ", fun=0x" + Long.toHexString(fun));
        }
        return null;
    }

}
