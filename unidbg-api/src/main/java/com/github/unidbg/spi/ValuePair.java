package com.github.unidbg.spi;

public interface ValuePair {

    void set(String key, Object value);
    <T> T get(String key);

}
