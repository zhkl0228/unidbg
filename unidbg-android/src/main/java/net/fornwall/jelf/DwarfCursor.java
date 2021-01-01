package net.fornwall.jelf;

public abstract class DwarfCursor {

    long cfa; /* canonical frame address; aka frame-/stack-pointer */
    public long ip; /* instruction pointer */

    final Long[] loc;

    protected DwarfCursor(Long[] loc) {
        this.loc = loc;
    }

}
