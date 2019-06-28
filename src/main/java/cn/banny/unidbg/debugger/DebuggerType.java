package cn.banny.unidbg.debugger;

public enum  DebuggerType {

    /**
     * simple debugger
     */
    SIMPLE,

    /**
     * gdb server
     */
    GDB_SERVER,

    /**
     * ida android server v7.3
     */
    @Deprecated
    ANDROID_SERVER_V73

}
