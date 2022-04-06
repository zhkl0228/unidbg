package com.github.unidbg.ios.objc;

import com.github.unidbg.PointerArg;
import com.github.unidbg.ios.struct.objc.ObjcObject;
import com.sun.jna.Pointer;

import java.util.Iterator;

public class NSArray implements Iterable<ObjcObject>, PointerArg {

    public static NSArray create(ObjcObject object) {
        return object == null ? null : new NSArray(object);
    }

    private final ObjcObject object;

    private NSArray(ObjcObject object) {
        this.object = object;
    }

    @Override
    public Pointer getPointer() {
        return object.getPointer();
    }

    private class NSArrayIterator implements Iterator<ObjcObject> {

        private final int count;

        public NSArrayIterator() {
            count = object.callObjcInt("count");
        }

        private int index;

        @Override
        public boolean hasNext() {
            return index < count;
        }
        @Override
        public ObjcObject next() {
            return object.callObjc("objectAtIndex:", index++);
        }
        @Override
        public void remove() {
            throw new UnsupportedOperationException();
        }
    }

    @Override
    public Iterator<ObjcObject> iterator() {
        return new NSArrayIterator();
    }

}
