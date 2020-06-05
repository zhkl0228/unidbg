package com.github.unidbg.ios;

class NeedLibrary {

    final String path;
    final boolean upward;
    final boolean weak;
    NeedLibrary(String path, boolean upward, boolean weak) {
        this.path = path;
        this.upward = upward;
        this.weak = weak;
    }

    @Override
    public String toString() {
        return (upward ? '?' : '*') + path;
    }
}
