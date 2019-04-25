package cn.banny.emulator.spi;

import cn.banny.emulator.Emulator;

public abstract class InitFunction {

    protected final long load_base;
    protected final String libName;
    public final long[] addresses;

    public InitFunction(long load_base, String libName, long...addresses) {
        this.load_base = load_base;
        this.libName = libName;
        this.addresses = addresses;
    }

    public abstract void call(Emulator emulator);

}
