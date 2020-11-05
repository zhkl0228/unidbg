package net.fornwall.jelf;

import com.github.unidbg.Utils;
import com.github.unidbg.utils.Inspector;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.nio.ByteBuffer;
import java.util.Iterator;

public class AndroidRelocationIterator implements Iterator<MemoizedObject<ElfRelocation>> {

    private static final Log log = LogFactory.getLog(AndroidRelocationIterator.class);

    private static final int RELOCATION_GROUPED_BY_INFO_FLAG = 1;
    private static final int RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG = 2;
    private static final int RELOCATION_GROUPED_BY_ADDEND_FLAG = 4;
    private static final int RELOCATION_GROUP_HAS_ADDEND_FLAG = 8;

    private long readSleb128() {
        return Utils.readSignedLeb128(buffer, objectSize == ElfFile.CLASS_32 ? 32 : 64);
    }

    private final int objectSize;
    private final ByteBuffer buffer;

    private long relocation_count_;
    private final ElfRelocation reloc_;

    private final boolean rela;

    public AndroidRelocationIterator(int objectSize, SymbolLocator symtab, ByteBuffer buffer, boolean rela) {
        this.objectSize = objectSize;
        this.buffer = buffer;
        this.rela = rela;
        reloc_ = new ElfRelocation(objectSize, symtab);

        relocation_count_ = readSleb128();
        reloc_.offset = readSleb128();

        relocation_index_ = 0;
        relocation_group_index_ = 0;
        group_size_ = 0;
    }

    private long relocation_index_, relocation_group_index_, group_size_;

    @Override
    public boolean hasNext() {
        boolean next = relocation_index_ < relocation_count_;
        if (!next && log.isDebugEnabled()) {
            byte[] remaining = new byte[buffer.remaining()];
            buffer.get(remaining);
            Inspector.inspect(remaining, "end");
        }
        return next;
    }

    @Override
    public MemoizedObject<ElfRelocation> next() {
        if (relocation_group_index_ == group_size_) {
            if (!read_group_fields()) {
                // Iterator is inconsistent state; it should not be called again
                // but in case it is let's make sure has_next() returns false.
                relocation_index_ = 0;
                relocation_count_ = 0;
                return null;
            }
        }

        if (is_relocation_grouped_by_offset_delta()) {
            reloc_.offset += group_r_offset_delta_;
        } else {
            reloc_.offset += readSleb128();
        }

        if (!is_relocation_grouped_by_info()) {
            reloc_.info = readSleb128();
        }

        if (is_relocation_group_has_addend() &&
                !is_relocation_grouped_by_addend()) {
            if (!rela) {
                throw new IllegalStateException("unexpected r_addend in android.rel section");
            }
            reloc_.addend += readSleb128();
        }

        relocation_index_++;
        relocation_group_index_++;

        try {
            final ElfRelocation copy = reloc_.clone();
            return new MemoizedObject<ElfRelocation>() {
                @Override
                protected ElfRelocation computeValue() throws ElfException {
                    return copy;
                }
            };
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException(e);
        }
    }

    private long group_flags_;
    private long group_r_offset_delta_;

    private boolean read_group_fields() {
        group_size_ = readSleb128();
        group_flags_ = readSleb128();

        if (is_relocation_grouped_by_offset_delta()) {
            group_r_offset_delta_ = readSleb128();
        }

        if (is_relocation_grouped_by_info()) {
            reloc_.info = readSleb128();
        }

        if (is_relocation_group_has_addend() &&
                is_relocation_grouped_by_addend()) {
            if (!rela) {
                throw new IllegalStateException("unexpected r_addend in android.rel section");
            }
            reloc_.addend += readSleb128();
        } else if (!is_relocation_group_has_addend()) {
            if (rela) {
                reloc_.addend = 0;
            }
        }

        relocation_group_index_ = 0;
        return true;
    }

    private boolean is_relocation_grouped_by_info() {
        return (group_flags_ & RELOCATION_GROUPED_BY_INFO_FLAG) != 0;
    }

    private boolean is_relocation_grouped_by_offset_delta() {
        return (group_flags_ & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG) != 0;
    }

    private boolean is_relocation_grouped_by_addend() {
        return (group_flags_ & RELOCATION_GROUPED_BY_ADDEND_FLAG) != 0;
    }

    private boolean is_relocation_group_has_addend() {
        return (group_flags_ & RELOCATION_GROUP_HAS_ADDEND_FLAG) != 0;
    }

    @Override
    public void remove() {
        throw new UnsupportedOperationException();
    }

}
