package com.github.unidbg.ios.struct;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class VMStatistics extends UnidbgStructure {

    public VMStatistics(Pointer p) {
        super(p);
    }

    public int free_count; /* # of pages free */
    public int active_count; /* # of pages active */
    public int inactive_count; /* # of pages inactive */
    public int wire_count; /* # of pages wired down */
    public int zero_fill_count; /* # of zero fill pages */
    public int reactivations; /* # of pages reactivated */
    public int pageins; /* # of pageins */
    public int pageouts; /* # of pageouts */
    public int faults; /* # of faults */
    public int cow_faults; /* # of copy-on-writes */
    public int lookups; /* object cache lookups */
    public int hits; /* object cache hits */

    public int purgeable_count; /* # of pages purgeable */
    public int purges; /* # of pages purged */

    public int speculative_count; /* # of pages speculative */

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("free_count", "active_count", "inactive_count", "wire_count", "zero_fill_count", "reactivations",
                "pageins", "pageouts", "faults", "cow_faults", "lookups", "hits", "purgeable_count", "purges", "speculative_count");
    }
}
