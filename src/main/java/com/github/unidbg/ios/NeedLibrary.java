package com.github.unidbg.ios;

class NeedLibrary {

    final String path;
    final boolean upward;
    NeedLibrary(String path, boolean upward) {
        this.path = path;
        this.upward = upward;
    }

    @Override
    public String toString() {
        return (upward ? '?' : '*') + path;
    }
}
