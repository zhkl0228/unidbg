package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.linux.android.dvm.wrapper.DvmInteger;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/** AbstractJni 常用 Java 层方法的默认实现。 */
public class JniBasicsTest {

    private AndroidEmulator emulator;
    private BaseVM vm;
    private final AbstractJni jni = new AbstractJni() {
    };

    @Before
    public void setUp() {
        emulator = AndroidEmulatorBuilder.for32Bit().addBackendFactory(new Unicorn2Factory(true)).build();
        vm = (BaseVM) emulator.createDalvikVM();
        vm.setJni(jni);
    }

    @After
    public void tearDown() throws Exception {
        emulator.close();
    }

    @Test
    public void stringOperations() {
        StringObject str = new StringObject(vm, "Hello World");

        StringObject sub = (StringObject) jni.callObjectMethodV(vm, str,
                "java/lang/String->substring(I)Ljava/lang/String;",
                vaList("java/lang/String", "substring", "(I)Ljava/lang/String;", 6));
        assertEquals("World", sub.value);

        StringObject range = (StringObject) jni.callObjectMethodV(vm, str,
                "java/lang/String->substring(II)Ljava/lang/String;",
                vaList("java/lang/String", "substring", "(II)Ljava/lang/String;", 0, 5));
        assertEquals("Hello", range.value);

        StringObject replaced = (StringObject) jni.callObjectMethodV(vm, str,
                "java/lang/String->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
                vaList("java/lang/String", "replaceAll",
                        "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
                        new StringObject(vm, "\\s+"), new StringObject(vm, "_")));
        assertEquals("Hello_World", replaced.value);

        assertEquals("Hello World".hashCode(), jni.callIntMethodV(vm, str,
                "java/lang/String->hashCode()I", vaList("java/lang/String", "hashCode", "()I")));

        assertTrue(jni.callBooleanMethodV(vm, str,
                "java/lang/String->equalsIgnoreCase(Ljava/lang/String;)Z",
                vaList("java/lang/String", "equalsIgnoreCase", "(Ljava/lang/String;)Z",
                        new StringObject(vm, "HELLO WORLD"))));
        assertEquals(0, jni.callIntMethodV(vm, str,
                "java/lang/String->compareToIgnoreCase(Ljava/lang/String;)I",
                vaList("java/lang/String", "compareToIgnoreCase", "(Ljava/lang/String;)I",
                        new StringObject(vm, "hello world"))));
    }

    @Test
    public void staticStringConversion() {
        DvmClass stringClass = vm.resolveClass("java/lang/String");

        assertEquals("42", ((StringObject) jni.callStaticObjectMethodV(vm, stringClass,
                "java/lang/String->valueOf(I)Ljava/lang/String;",
                vaList("java/lang/String", "valueOf", "(I)Ljava/lang/String;", 42))).value);
        assertEquals("42", ((StringObject) jni.callStaticObjectMethodV(vm, stringClass,
                "java/lang/String->valueOf(J)Ljava/lang/String;",
                vaList("java/lang/String", "valueOf", "(J)Ljava/lang/String;", 42L))).value);
        assertEquals("true", ((StringObject) jni.callStaticObjectMethodV(vm, stringClass,
                "java/lang/String->valueOf(Z)Ljava/lang/String;",
                vaList("java/lang/String", "valueOf", "(Z)Ljava/lang/String;", 1))).value);
        assertEquals("42", ((StringObject) jni.callStaticObjectMethodV(vm, vm.resolveClass("java/lang/Integer"),
                "java/lang/Integer->toString(I)Ljava/lang/String;",
                vaList("java/lang/Integer", "toString", "(I)Ljava/lang/String;", 42))).value);

        assertEquals("7", ((StringObject) jni.callObjectMethodV(vm, DvmInteger.valueOf(vm, 7),
                "java/lang/Integer->toString()Ljava/lang/String;",
                vaList("java/lang/Integer", "toString", "()Ljava/lang/String;"))).value);
    }

    @Test
    public void stringBuilderAndBuffer() {
        DvmObject<?> builder = jni.allocObject(vm, vm.resolveClass("java/lang/StringBuilder"),
                "java/lang/StringBuilder->allocObject");

        jni.callObjectMethodV(vm, builder,
                "java/lang/StringBuilder->append(Ljava/lang/String;)Ljava/lang/StringBuilder;",
                vaList("java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;",
                        new StringObject(vm, "abc")));
        jni.callObjectMethodV(vm, builder,
                "java/lang/StringBuilder->append(I)Ljava/lang/StringBuilder;",
                vaList("java/lang/StringBuilder", "append", "(I)Ljava/lang/StringBuilder;", 42));
        jni.callObjectMethodV(vm, builder,
                "java/lang/StringBuilder->append(J)Ljava/lang/StringBuilder;",
                vaList("java/lang/StringBuilder", "append", "(J)Ljava/lang/StringBuilder;", 7L));
        jni.callObjectMethodV(vm, builder,
                "java/lang/StringBuilder->append(C)Ljava/lang/StringBuilder;",
                vaList("java/lang/StringBuilder", "append", "(C)Ljava/lang/StringBuilder;", (int) 'X'));
        jni.callObjectMethodV(vm, builder,
                "java/lang/StringBuilder->append(Ljava/lang/CharSequence;II)Ljava/lang/StringBuilder;",
                vaList("java/lang/StringBuilder", "append", "(Ljava/lang/CharSequence;II)Ljava/lang/StringBuilder;",
                        new StringObject(vm, "abcd"), 1, 3));

        assertEquals("abc427Xbc", ((StringObject) jni.callObjectMethodV(vm, builder,
                "java/lang/StringBuilder->toString()Ljava/lang/String;",
                vaList("java/lang/StringBuilder", "toString", "()Ljava/lang/String;"))).value);

        DvmObject<?> buffer = jni.newObjectV(vm, vm.resolveClass("java/lang/StringBuffer"),
                "java/lang/StringBuffer-><init>()V",
                vaList("java/lang/StringBuffer", "<init>", "()V"));
        jni.callObjectMethodV(vm, buffer,
                "java/lang/StringBuffer->append(Ljava/lang/String;)Ljava/lang/StringBuffer;",
                vaList("java/lang/StringBuffer", "append", "(Ljava/lang/String;)Ljava/lang/StringBuffer;",
                        new StringObject(vm, "buf")));

        assertEquals("buf", ((StringObject) jni.callObjectMethodV(vm, buffer,
                "java/lang/StringBuffer->toString()Ljava/lang/String;",
                vaList("java/lang/StringBuffer", "toString", "()Ljava/lang/String;"))).value);
    }

    @Test
    public void mapOperations() {
        DvmObject<?> map = jni.allocObject(vm, vm.resolveClass("java/util/HashMap"),
                "java/util/HashMap->allocObject");

        assertTrue(jni.callBooleanMethodV(vm, map, "java/util/Map->isEmpty()Z",
                vaList("java/util/Map", "isEmpty", "()Z")));

        jni.callObjectMethodV(vm, map, "java/util/Map->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
                vaList("java/util/Map", "put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
                        new StringObject(vm, "key"), new StringObject(vm, "value")));

        assertFalse(jni.callBooleanMethodV(vm, map, "java/util/Map->isEmpty()Z",
                vaList("java/util/Map", "isEmpty", "()Z")));
        assertEquals(1, jni.callIntMethodV(vm, map, "java/util/Map->size()I",
                vaList("java/util/Map", "size", "()I")));

        StringObject value = (StringObject) jni.callObjectMethodV(vm, map,
                "java/util/Map->get(Ljava/lang/Object;)Ljava/lang/Object;",
                vaList("java/util/Map", "get", "(Ljava/lang/Object;)Ljava/lang/Object;",
                        new StringObject(vm, "key")));
        assertEquals("value", value.value);

        DvmObject<?> keySet = jni.callObjectMethodV(vm, map, "java/util/Map->keySet()Ljava/util/Set;",
                vaList("java/util/Map", "keySet", "()Ljava/util/Set;"));
        ArrayObject keys = (ArrayObject) jni.callObjectMethodV(vm, keySet,
                "java/util/Set->toArray()[Ljava/lang/Object;",
                vaList("java/util/Set", "toArray", "()[Ljava/lang/Object;"));
        assertEquals(1, keys.length());
        assertEquals("key", ((StringObject) keys.getValue()[0]).value);

        DvmObject<?> entrySet = jni.callObjectMethodV(vm, map, "java/util/Map->entrySet()Ljava/util/Set;",
                vaList("java/util/Map", "entrySet", "()Ljava/util/Set;"));
        DvmObject<?> iterator = jni.callObjectMethodV(vm, entrySet,
                "java/util/Set->iterator()Ljava/util/Iterator;",
                vaList("java/util/Set", "iterator", "()Ljava/util/Iterator;"));
        assertTrue(jni.callBooleanMethodV(vm, iterator, "java/util/Iterator->hasNext()Z",
                vaList("java/util/Iterator", "hasNext", "()Z")));

        DvmObject<?> entry = jni.callObjectMethodV(vm, iterator,
                "java/util/Iterator->next()Ljava/lang/Object;",
                vaList("java/util/Iterator", "next", "()Ljava/lang/Object;"));
        assertEquals("key", ((StringObject) jni.callObjectMethodV(vm, entry,
                "java/util/Map$Entry->getKey()Ljava/lang/Object;",
                vaList("java/util/Map$Entry", "getKey", "()Ljava/lang/Object;"))).value);
        assertEquals("value", ((StringObject) jni.callObjectMethodV(vm, entry,
                "java/util/Map$Entry->getValue()Ljava/lang/Object;",
                vaList("java/util/Map$Entry", "getValue", "()Ljava/lang/Object;"))).value);
    }

    @Test
    public void androidHelpersAndDate() {
        DvmClass textUtils = vm.resolveClass("android/text/TextUtils");
        assertTrue(jni.callStaticBooleanMethodV(vm, textUtils,
                "android/text/TextUtils->isEmpty(Ljava/lang/CharSequence;)Z",
                vaList("android/text/TextUtils", "isEmpty", "(Ljava/lang/CharSequence;)Z",
                        new StringObject(vm, ""))));
        assertFalse(jni.callStaticBooleanMethodV(vm, textUtils,
                "android/text/TextUtils->isEmpty(Ljava/lang/CharSequence;)Z",
                vaList("android/text/TextUtils", "isEmpty", "(Ljava/lang/CharSequence;)Z",
                        new StringObject(vm, "x"))));

        assertFalse(jni.callStaticBooleanMethodV(vm, vm.resolveClass("android/os/Debug"),
                "android/os/Debug->isDebuggerConnected()Z",
                vaList("android/os/Debug", "isDebuggerConnected", "()Z")));

        DvmObject<?> date = jni.newObjectV(vm, vm.resolveClass("java/util/Date"),
                "java/util/Date-><init>()V", vaList("java/util/Date", "<init>", "()V"));
        assertTrue(jni.callLongMethodV(vm, date, "java/util/Date->getTime()J",
                vaList("java/util/Date", "getTime", "()J")) > 0);

        assertEquals("Application", ((StringObject) jni.callObjectMethodV(vm,
                vm.resolveClass("android/app/Application"),
                "java/lang/Class->getSimpleName()Ljava/lang/String;",
                vaList("java/lang/Class", "getSimpleName", "()Ljava/lang/String;"))).value);
    }

    private VaList vaList(String className, String methodName, String args, Object... values) {
        DvmMethod method = new DvmMethod(vm.resolveClass(className), methodName, args, false);
        Object[] normalized = new Object[values.length];
        for (int i = 0; i < values.length; i++) {
            Object value = values[i];
            normalized[i] = value instanceof DvmObject ? vm.addLocalObject((DvmObject<?>) value) : value;
        }
        return new TestVaList(vm, method, normalized);
    }

    private static final class TestVaList extends VaList {

        private TestVaList(BaseVM vm, DvmMethod method, Object[] values) {
            super(vm, method);
            Collections.addAll(args, values);
        }
    }
}
