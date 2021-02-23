package com.github.unidbg;

import java.io.PrintStream;

public interface TraceHook {

    void setRedirect(PrintStream redirect);

    void stopTrace();

}
