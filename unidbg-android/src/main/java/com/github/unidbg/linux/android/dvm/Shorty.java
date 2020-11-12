package com.github.unidbg.linux.android.dvm;

import java.lang.reflect.Array;

public class Shorty {

    private final int arrayDimensions;
    private final char type;
    private String binaryName;

    Shorty(int arrayDimensions, char type) {
        this.arrayDimensions = arrayDimensions;
        this.type = type;
    }

    final void setBinaryName(String binaryName) {
        this.binaryName = binaryName;
    }

    public char getType() {
        return arrayDimensions > 0 ? 'L' : type;
    }

    private static Class<?> getPrimitiveType(char c) {
        switch (c) {
            case 'B':
                return byte.class;
            case 'C':
                return char.class;
            case 'I':
                return int.class;
            case 'S':
                return short.class;
            case 'Z':
                return boolean.class;
            case 'F':
                return float.class;
            case 'D':
                return double.class;
            case 'J':
                return long.class;
            default:
                return null;
        }
    }

    public Class<?> decodeType(ClassLoader classLoader) {
        if (classLoader == null) {
            classLoader = Shorty.class.getClassLoader();
        }

        Class<?> clazz = getPrimitiveType(getType());
        if (clazz != null) {
            return clazz;
        }
        int dimensions = this.arrayDimensions;
        if (dimensions > 0) {
            try {
                clazz = binaryName == null ? getPrimitiveType(type) : classLoader.loadClass(binaryName.replace('/', '.'));
                if (clazz == null) {
                    throw new IllegalStateException("type=" + type);
                }
                while (dimensions-- > 0) {
                    clazz = Array.newInstance(clazz, 1).getClass();
                }
                return clazz;
            } catch (ClassNotFoundException ignored) {
            }
            return null;
        } else {
            if (binaryName == null) {
                throw new IllegalStateException("binaryName is null");
            }
            try {
                clazz = classLoader.loadClass(binaryName.replace('/', '.'));
            } catch (ClassNotFoundException ignored) {
            }
            return clazz;
        }
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < arrayDimensions; i++) {
            sb.append('[');
        }
        sb.append(type);
        if (binaryName != null) {
            sb.append(binaryName).append(';');
        }
        return sb.toString();
    }

}
