package cn.banny.unidbg.debugger;

public interface DebugServer extends Debugger, Runnable {

    int DEFAULT_PORT = 23946;

    int PACKET_SIZE = 1024;

}
