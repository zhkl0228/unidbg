package net.fornwall.jelf;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.unwind.Frame;
import com.github.unidbg.unwind.Unwinder;
import com.github.unidbg.utils.Inspector;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Stack;

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
    private static final int DW_EH_PE_udata1 = 0x0D;
    private static final int DW_EH_PE_block = 0x0F;
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
    private static long readULEB128(ElfDataIn dataIn, Off off) {
        long result = 0;
        int shift = 0;
        int b;
        do {
            b = dataIn.readUnsignedByte(); off.pos++;
            result |= (long) (b & 0x7f) << shift;
            shift += 7;
        } while ((b & 0x80) != 0);
        return result;
    }

    /* read a sleb128 encoded value and advance pointer */
    private static long readSLEB128(ElfDataIn dataIn, Off off) {
        long result = 0;
        int shift = 0;
        int b;
        do {
            b = dataIn.readUnsignedByte(); off.pos++;
            result |= (long) (b & 0x7f) << shift;
            shift += 7;
        } while ((b & 0x80) != 0);
        if (((b & 0x40) != 0)) {
            result |= -(1L << shift);
        }
        return result;
    }

    private static long readEncodedPointer(ElfDataIn dataIn, int encoding, Off off) {
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
                result = readULEB128(dataIn, off);
                break;
            case DW_EH_PE_udata1:
                result = dataIn.readUnsignedByte(); off.pos++;
                break;
            case DW_EH_PE_udata2:
                result = dataIn.readShort() & 0xffffL; off.pos += 2;
                break;
            case DW_EH_PE_udata4:
                result = dataIn.readInt() & 0xffffffffL; off.pos += 4;
                break;
            case DW_EH_PE_sdata2:
                result = dataIn.readShort(); off.pos += 2;
                break;
            case DW_EH_PE_sdata4:
                result = dataIn.readInt(); off.pos += 4;
                break;
            case DW_EH_PE_udata8:
            case DW_EH_PE_sdata8:
                result = dataIn.readLong(); off.pos += 8;
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

        FDE fde = dwarf_get_fde(entry.address, fun);
        if (log.isDebugEnabled()) {
            log.debug("dwarf_step entry=" + entry + ", fun=0x" + Long.toHexString(fun) + ", fde=" + fde + ", module=" + module);
        }
        dwarf_loc_t loc = fde == null ? null : dwarf_get_loc(fde, fun);
        if (loc != null) {
            UnidbgPointer vsp;
            switch (loc.cfa_rule.type) {
                case DW_LOC_REGISTER:
                    vsp = UnidbgPointer.pointer(emulator, context.loc[(int) loc.cfa_rule.values[0]] + loc.cfa_rule.values[1]);
                    assert vsp != null;
                    context.loc[emulator.is32Bit() ? DwarfCursor32.SP : DwarfCursor64.SP] = vsp.peer;
                    if (log.isDebugEnabled()) {
                        log.debug("dwarf_step cfa = " + (emulator.is32Bit() ? "r" : "x") + loc.cfa_rule.values[0] + " + " + loc.cfa_rule.values[1] + " => 0x" + Long.toHexString(vsp.peer));
                    }
                    break;
                case DW_LOC_VAL_EXPRESSION:
                default:
                    throw new UnsupportedOperationException("dwarf_step type=" + loc.cfa_rule.type);
            }

            for (int i = 0; i < loc.reg_rules.length; i++) {
                dwarf_loc_rule_t rule = loc.reg_rules[i];
                if (rule == null) {
                    continue;
                }

                switch (rule.type) {
                    case DW_LOC_OFFSET:
                        UnidbgPointer value = vsp.getPointer(rule.values[0]);
                        context.loc[i] = value == null ? 0L : value.peer;
                        if (log.isDebugEnabled()) {
                            log.debug("dwarf_step " + (emulator.is32Bit() ? "r" : "x") + i + " + (" + rule.values[0] + ") => 0x" + Long.toHexString(context.loc[i]));
                        }
                        break;
                    case DW_LOC_VAL_OFFSET:
                    case DW_LOC_REGISTER:
                    case DW_LOC_EXPRESSION:
                    case DW_LOC_VAL_EXPRESSION:
                    case DW_LOC_UNDEFINED:
                    default:
                        throw new UnsupportedOperationException("dwarf_step type=" + rule.type);
                }
            }

            long ip = context.loc[fde.cie.return_address_register];
            if (log.isDebugEnabled()) {
                log.debug("dwarf_step cfa=0x" + Long.toHexString(vsp.peer) + ", ip=0x" + Long.toHexString(ip));
            }

            context.ip = ip;
            context.cfa = vsp.peer;
            Frame frame = unwinder.createFrame(UnidbgPointer.pointer(emulator, ip), UnidbgPointer.pointer(emulator, context.cfa));
            if (frame != null) {
                context.ip = frame.ip.peer;
            }
            return frame;
        }

        return null;
    }

    private static class dwarf_loc_rule_t {
        int type;
        final long[] values = new long[2];
        final dwarf_loc_rule_t copy() {
            dwarf_loc_rule_t copy = new dwarf_loc_rule_t();
            copy.type = this.type;
            System.arraycopy(values, 0, copy.values, 0, values.length);
            return copy;
        }
    }

    private static final int DWARF_REG_NUM = 0x100;

    private static class dwarf_loc_t {
        final dwarf_loc_rule_t cfa_rule;
        final dwarf_loc_rule_t[] reg_rules;
        dwarf_loc_t() {
            cfa_rule = new dwarf_loc_rule_t();
            reg_rules = new dwarf_loc_rule_t[DWARF_REG_NUM];
        }
        dwarf_loc_t(dwarf_loc_t copy) {
            cfa_rule = copy.cfa_rule.copy();
            reg_rules = new dwarf_loc_rule_t[DWARF_REG_NUM];
            for (int i = 0; i < DWARF_REG_NUM; i++) {
                dwarf_loc_rule_t src = copy.reg_rules[i];
                if (src != null) {
                    reg_rules[i] = src.copy();
                }
            }
        }
        dwarf_loc_rule_t get_reg_rule(long i) {
            dwarf_loc_rule_t rule = reg_rules[(int) i];
            if (rule == null) {
                rule = new dwarf_loc_rule_t();
                reg_rules[(int) i] = rule;
            }
            return rule;
        }
    }

    private static class dwarf_cfa_t {
        final int[] operand_types;
        dwarf_cfa_t(int t1, int t2) {
            this.operand_types = new int[] { t1, t2 };
        }
    }

    private static final dwarf_cfa_t[] dwarf_cfa_table = new dwarf_cfa_t[]{
/* 0x00 */ new dwarf_cfa_t(DW_EH_PE_omit, DW_EH_PE_omit),
/* 0x01 */ new dwarf_cfa_t(DW_EH_PE_absptr, DW_EH_PE_omit),
/* 0x02 */ new dwarf_cfa_t(DW_EH_PE_udata1,  DW_EH_PE_omit),
/* 0x03 */ new dwarf_cfa_t(DW_EH_PE_udata2,  DW_EH_PE_omit),
/* 0x04 */ new dwarf_cfa_t(DW_EH_PE_udata4,  DW_EH_PE_omit),
/* 0x05 */ new dwarf_cfa_t(DW_EH_PE_uleb128, DW_EH_PE_uleb128),
/* 0x06 */ new dwarf_cfa_t(DW_EH_PE_uleb128, DW_EH_PE_omit),
/* 0x07 */ new dwarf_cfa_t(DW_EH_PE_uleb128, DW_EH_PE_omit),
/* 0x08 */ new dwarf_cfa_t(DW_EH_PE_uleb128, DW_EH_PE_omit),
/* 0x09 */ new dwarf_cfa_t(DW_EH_PE_uleb128, DW_EH_PE_uleb128),
/* 0x0a */ new dwarf_cfa_t(DW_EH_PE_omit,    DW_EH_PE_omit),
/* 0x0b */ new dwarf_cfa_t(DW_EH_PE_omit,    DW_EH_PE_omit),
/* 0x0c */ new dwarf_cfa_t(DW_EH_PE_uleb128, DW_EH_PE_uleb128),
/* 0x0d */ new dwarf_cfa_t(DW_EH_PE_uleb128, DW_EH_PE_omit),
/* 0x0e */ new dwarf_cfa_t(DW_EH_PE_uleb128, DW_EH_PE_omit),
/* 0x0f */ new dwarf_cfa_t(DW_EH_PE_block,   DW_EH_PE_omit),
/* 0x10 */ new dwarf_cfa_t(DW_EH_PE_uleb128, DW_EH_PE_block),
/* 0x11 */ new dwarf_cfa_t(DW_EH_PE_uleb128, DW_EH_PE_sleb128),
/* 0x12 */ new dwarf_cfa_t(DW_EH_PE_uleb128, DW_EH_PE_sleb128),
/* 0x13 */ new dwarf_cfa_t(DW_EH_PE_sleb128, DW_EH_PE_omit),
/* 0x14 */ new dwarf_cfa_t(DW_EH_PE_uleb128, DW_EH_PE_uleb128),
/* 0x15 */ new dwarf_cfa_t(DW_EH_PE_uleb128, DW_EH_PE_sleb128),
/* 0x16 */ new dwarf_cfa_t(DW_EH_PE_uleb128, DW_EH_PE_block),
/* 0x17 */ null,
/* 0x18 */ null,
/* 0x19 */ null,
/* 0x1a */ null,
/* 0x1b */ null,
/* 0x1c */ null,
/* 0x1d */ null,
/* 0x1e */ null,
/* 0x1f */ null,
/* 0x20 */ null,
/* 0x21 */ null,
/* 0x22 */ null,
/* 0x23 */ null,
/* 0x24 */ null,
/* 0x25 */ null,
/* 0x26 */ null,
/* 0x27 */ null,
/* 0x28 */ null,
/* 0x29 */ null,
/* 0x2a */ null,
/* 0x2b */ null,
/* 0x2c */ null,
/* 0x2d */ null,
/* 0x2e */ new dwarf_cfa_t(DW_EH_PE_uleb128, DW_EH_PE_omit),
/* 0x2f */ new dwarf_cfa_t(DW_EH_PE_uleb128, DW_EH_PE_uleb128),
/* 0x30 */ null,
/* 0x31 */ null,
/* 0x32 */ null,
/* 0x33 */ null,
/* 0x34 */ null,
/* 0x35 */ null,
/* 0x36 */ null,
/* 0x37 */ null,
/* 0x38 */ null,
/* 0x39 */ null,
/* 0x3a */ null,
/* 0x3b */ null,
/* 0x3c */ null,
/* 0x3d */ null,
/* 0x3e */ null,
/* 0x3f */ null,
    };

    // location rule type
    private static final int DW_LOC_INVALID = 0;
    private static final int DW_LOC_UNDEFINED = 1;
    private static final int DW_LOC_OFFSET = 2;
    private static final int DW_LOC_VAL_OFFSET = 3;
    private static final int DW_LOC_REGISTER = 4;
    private static final int DW_LOC_EXPRESSION = 5;
    private static final int DW_LOC_VAL_EXPRESSION = 6;

    private static dwarf_loc_t dwarf_get_loc(FDE fde, final long pc) {
        long cur_pc = fde.pc_start;
        dwarf_loc_t loc;
        long[] operands = new long[2];

        dwarf_loc_t loc_init = new dwarf_loc_t();
        dwarf_loc_t loc_pc;
        loc = loc_init;
        Stack<dwarf_loc_t> loc_node_stack = new Stack<>();

        byte[] instructions = fde.merge();
        boolean stepped = false;
        for (int i = 0; i < instructions.length; i++) {
            if (cur_pc > pc) {
                stepped = true;
                break; // have stepped to the LOC
            }

            if (i == fde.cie.cfa_instructions.length) {
                loc_pc = new dwarf_loc_t(loc_init);
                loc = loc_pc;
                stepped = true;
            }

            int op = instructions[i] & 0xff;
            int cfa_op = op >> 6;
            int cfa_op_ext = op & 0x3f;
            if (log.isDebugEnabled()) {
                log.debug("dwarf_get_loc i=" + i + ", op=0x" + Integer.toHexString(op) + ", cfa_op=" + cfa_op + ", cfa_op_ext=0x" + Integer.toHexString(cfa_op_ext) + ", cur_pc=0x" + Long.toHexString(cur_pc));
            }

            switch (cfa_op) {
                case 0x1: // DW_CFA_advance_loc
                    long step = cfa_op_ext * fde.cie.code_alignment_factor;
                    cur_pc += step;
                    if (log.isDebugEnabled()) {
                        log.debug("DW_CFA_advance_loc: " + step + " to " + Long.toHexString(cur_pc));
                    }
                    break;
                case 0x2: { // DW_CFA_offset
                    Off off = new Off(0);
                    ElfDataIn dataIn = new ElfBuffer(Arrays.copyOfRange(instructions, i + 1, instructions.length));
                    long v64 = readULEB128(dataIn, off);
                    dwarf_loc_rule_t rule = loc.get_reg_rule(cfa_op_ext);
                    rule.type = DW_LOC_OFFSET;
                    rule.values[0] = v64 * fde.cie.data_alignment_factor;
                    i += off.pos;
                    if (log.isDebugEnabled()) {
                        log.debug("DW_CFA_offset: r" + cfa_op_ext + " at cfa" + rule.values[0]);
                    }
                    break;
                }
                case 0x3: // DW_CFA_restore
                    loc.reg_rules[cfa_op_ext] = loc_init.reg_rules[cfa_op_ext];
                    if (log.isDebugEnabled()) {
                        log.debug("DW_CFA_restore: r" + cfa_op_ext);
                    }
                    break;
                case 0:
                default: {
                    dwarf_cfa_t cfa = dwarf_cfa_table[cfa_op_ext];
                    if (cfa == null) { // illegal cfa
                        throw new IllegalStateException("dwarf_get_loc illegal cfa");
                    }
                    for (int m = 0; m < 2; m++) {
                        int type = cfa.operand_types[m];
                        if (type == DW_EH_PE_omit) {
                            break;
                        } else if (type == DW_EH_PE_block) {
                            throw new IllegalStateException("dwarf_get_loc DW_EH_PE_block");
                        } else {
                            Off off = new Off(0);
                            ElfDataIn dataIn = new ElfBuffer(Arrays.copyOfRange(instructions, i + 1, instructions.length));
                            long v64 = readEncodedPointer(dataIn, type, off);
                            operands[m] = v64;
                            i += off.pos;
                        }
                    }
                    switch (cfa_op_ext) {
                        case 0x00: // DW_CFA_nop
                            if (log.isDebugEnabled()) {
                                log.debug("DW_CFA_nop");
                            }
                            break;
                        case 0x01: // DW_CFA_set_loc
                            cur_pc = operands[0];
                            break;
                        case 0x02: // DW_CFA_advance_loc1
                            step = operands[0] * fde.cie.code_alignment_factor;
                            cur_pc += step;
                            if (log.isDebugEnabled()) {
                                log.debug("DW_CFA_advance_loc1: " + step + " to " + Long.toHexString(cur_pc));
                            }
                            break;
                        case 0x03: // DW_CFA_advance_loc2
                        case 0x04: // DW_CFA_advance_loc3
                            cur_pc += operands[0] * fde.cie.code_alignment_factor;
                            break;
                        case 0x05: // DW_CFA_offset_extended
                            dwarf_loc_rule_t rule = loc.get_reg_rule(operands[0]);
                            rule.type = DW_LOC_OFFSET;
                            rule.values[0] = operands[1];
                            break;
                        case 0x06: // DW_CFA_restore_extended
                            loc.reg_rules[(int) operands[0]] = loc_init.reg_rules[(int) operands[0]];
                            break;
                        case 0x07: // DW_CFA_undefined
                            rule = loc.get_reg_rule(operands[0]);
                            rule.type = DW_LOC_UNDEFINED;
                            break;
                        case 0x08: // DW_CFA_same_value
                            rule = loc.get_reg_rule(operands[0]);
                            rule.type = DW_LOC_INVALID;
                            break;
                        case 0x09: // DW_CFA_register
                            rule = loc.get_reg_rule(operands[0]);
                            rule.type = DW_LOC_REGISTER;
                            rule.values[0] = operands[1];
                            break;
                        case 0x0a: // DW_CFA_remember_state
                            dwarf_loc_t loc_node = new dwarf_loc_t(loc);
                            loc_node_stack.push(loc_node);
                            break;
                        case 0x0b: // DW_CFA_restore_state
                            loc_node = loc_node_stack.pop();
                            loc_pc = new dwarf_loc_t(loc_node);
                            loc = loc_pc;
                            break;
                        case 0x0c: // DW_CFA_def_cfa
                            loc.cfa_rule.type = DW_LOC_REGISTER;
                            loc.cfa_rule.values[0] = operands[0];
                            loc.cfa_rule.values[1] = operands[1];
                            if (log.isDebugEnabled()) {
                                log.debug("DW_CFA_def_cfa: r" + operands[0] + " ofs " + operands[1]);
                            }
                            break;
                        case 0x0d: // DW_CFA_def_cfa_register
                            if (loc.cfa_rule.type != DW_LOC_REGISTER) {
                                throw new IllegalStateException("NOT DW_LOC_REGISTER");
                            } else {
                                loc.cfa_rule.values[0] = operands[0];
                            }
                            break;
                        case 0x0e: // DW_CFA_def_cfa_offset
                            if (loc.cfa_rule.type != DW_LOC_REGISTER) {
                                throw new IllegalStateException("NOT DW_LOC_REGISTER");
                            } else {
                                loc.cfa_rule.values[1] = operands[0];
                                if (log.isDebugEnabled()) {
                                    log.debug("DW_CFA_def_cfa_offset: " + operands[0]);
                                }
                            }
                            break;
                        default:
                            throw new IllegalStateException("dwarf_get_loc cfa_op=" + cfa_op + ", i=" + i + ", cfa_op_ext=0x" + Integer.toHexString(cfa_op_ext));
                    }
                }
            }
        }

        return stepped ? loc : loc_init;
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
        final byte[] merge() {
            byte[] instructions = new byte[cie.cfa_instructions.length + cfa_instructions.length];
            System.arraycopy(cie.cfa_instructions, 0, instructions, 0, cie.cfa_instructions.length);
            System.arraycopy(cfa_instructions, 0, instructions, cie.cfa_instructions.length, cfa_instructions.length);
            return instructions;
        }
    }

    private FDE dwarf_get_fde(long fde_offset, long fun) {
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
        if (fun >= pc_end) {
            return null;
        }

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
            throw new UnsupportedOperationException("64bits DWARF CIE");
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
        ByteArrayOutputStream baos = new ByteArrayOutputStream(8);
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
