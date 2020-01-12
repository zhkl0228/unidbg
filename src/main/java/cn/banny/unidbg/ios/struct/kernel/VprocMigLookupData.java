package cn.banny.unidbg.ios.struct.kernel;

import cn.banny.unidbg.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class VprocMigLookupData extends UnicornStructure {

    public VprocMigLookupData(Pointer p) {
        super(p);
    }

    public int ret;
    public int size;
    public AuditToken au_tok;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("ret", "size", "au_tok");
    }

}
