package com.github.unidbg.linux.android.dvm.array;

import com.github.unidbg.linux.android.dvm.Array;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.StringObject;
import com.github.unidbg.linux.android.dvm.VM;

import java.util.Arrays;

public class ArrayObject extends BaseArray<DvmObject<?>[]> implements Array<DvmObject<?>[]> {

    @SuppressWarnings("unused")
    public static ArrayObject newStringArray(VM vm, String... strings) {
        StringObject[] objects = new StringObject[strings.length];
        for (int i = 0; i < strings.length; i++) {
            String str = strings[i];
            if (str != null) {
                objects[i] = new StringObject(vm, str);
            }
        }
        return new ArrayObject(objects);
    }

    public static ArrayObject newObjectArray(DvmClass elementClass, DvmObject<?>... value) {
        String elementName = elementClass.getClassName();
        String arrayName = elementName.startsWith("[") ? "[" + elementName : "[L" + elementName + ";";
        return new ArrayObject(elementClass.vm.resolveClass(arrayName), value);
    }

    public ArrayObject(DvmObject<?>... value) {
        super(null, value);
    }

    private ArrayObject(DvmClass objectType, DvmObject<?>[] value) {
        super(objectType, value);
    }

    /**
     * Every object array is an Object[], Object, Cloneable and Serializable, whether or not its component type is known.
     */
    @Override
    protected boolean isInstanceOf(DvmClass dvmClass) {
        if (super.isInstanceOf(dvmClass)) {
            return true;
        }
        switch (dvmClass.getClassName()) {
            case "[Ljava/lang/Object;":
            case "java/lang/Object":
            case "java/lang/Cloneable":
            case "java/io/Serializable":
                return true;
            default:
                return false;
        }
    }

    @Override
    public int length() {
        return value.length;
    }

    @Override
    public void setData(int start, DvmObject<?>[] data) {
        System.arraycopy(data, 0, value, start, data.length);
    }

    @Override
    public String toString() {
        return Arrays.toString(value);
    }
}
