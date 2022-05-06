package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.context.Arm64RegisterContext;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.linux.android.dvm.apk.Apk;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.android.dvm.array.DoubleArray;
import com.github.unidbg.linux.android.dvm.array.FloatArray;
import com.github.unidbg.linux.android.dvm.array.IntArray;
import com.github.unidbg.linux.android.dvm.array.PrimitiveArray;
import com.github.unidbg.linux.android.dvm.array.ShortArray;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

public class DalvikVM64 extends BaseVM implements VM {

    private static final Log log = LogFactory.getLog(DalvikVM64.class);

    private final UnidbgPointer _JavaVM;
    private final UnidbgPointer _JNIEnv;

    public DalvikVM64(AndroidEmulator emulator, File apkFile) {
        super(emulator, apkFile);

        final SvcMemory svcMemory = emulator.getSvcMemory();
        _JavaVM = svcMemory.allocate(emulator.getPointerSize(), "_JavaVM");

        Pointer _GetVersion = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return JNI_VERSION_1_8;
            }
        });

        Pointer _DefineClass = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _FindClass = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                Pointer env = context.getPointerArg(0);
                Pointer className = context.getPointerArg(1);
                String name = className.getString(0);

                boolean notFound = notFoundClassSet.contains(name);
                if (verbose) {
                    if (notFound) {
                        System.out.printf("JNIEnv->FindNoClass(%s) was called from %s%n", name, context.getLRPointer());
                    } else {
                        System.out.printf("JNIEnv->FindClass(%s) was called from %s%n", name, context.getLRPointer());
                    }
                }

                if (notFound) {
                    throwable = resolveClass("java/lang/NoClassDefFoundError").newObject(name);
                    return 0;
                }

                DvmClass dvmClass = resolveClass(name);
                long hash = dvmClass.hashCode() & 0xffffffffL;
                if (log.isDebugEnabled()) {
                    log.debug("FindClass env=" + env + ", className=" + name + ", hash=0x" + Long.toHexString(hash));
                }
                return hash;
            }
        });

        Pointer _FromReflectedMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _FromReflectedField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _ToReflectedMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = null;
                if (dvmClass != null) {
                    dvmMethod = dvmClass.getStaticMethod(jmethodID.toIntPeer());
                    if (dvmMethod == null) {
                        dvmMethod = dvmClass.getMethod(jmethodID.toIntPeer());
                    }
                }
                if (log.isDebugEnabled()) {
                    log.debug("ToReflectedMethod clazz=" + dvmClass + ", jmethodID=" + jmethodID + ", lr=" + context.getLRPointer());
                }
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    if (verbose) {
                        System.out.printf("JNIEnv->ToReflectedMethod(%s, \"%s\", %s) was called from %s%n", dvmClass.getClassName(), dvmMethod.methodName, dvmMethod.isStatic ? "is static" : "not static", context.getLRPointer());
                    }

                    return addLocalObject(dvmMethod.toReflectedMethod());
                }
            }
        }) ;

        Pointer _GetSuperclass = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                if (verbose) {
                    System.out.printf("JNIEnv->GetSuperClass(%s) was called from %s%n", dvmClass, context.getLRPointer());
                }
                if (dvmClass.getClassName().equals("java/lang/Object")) {
                    log.debug("JNIEnv->GetSuperClass was called, class = " + dvmClass.getClassName() + " According to Java Native Interface Specification, " +
                            "If clazz specifies the class Object, returns NULL.");
                    throw new BackendException();
                }
                DvmClass superClass = dvmClass.getSuperclass();
                if (superClass == null) {
                    if (log.isDebugEnabled()) {
                        log.debug("JNIEnv->GetSuperClass was called, class = " + dvmClass.getClassName() + ", superClass get failed.");
                    }
                    throw new BackendException();
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("JNIEnv->GetSuperClass was called, class = " + dvmClass.getClassName() + ", superClass = " + superClass.getClassName());
                    }
                    return superClass.hashCode();
                }
            }
        });

        Pointer _IsAssignableFrom = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _ToReflectedField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _Throw = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                log.warn("Throw dvmObject=" + dvmObject + ", class=" + (dvmObject != null ? dvmObject.getObjectType() : null));
                throwable = dvmObject;
                return 0;
            }
        });

        Pointer _ThrowNew = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _ExceptionOccurred = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                long exception = throwable == null ? JNI_NULL : (throwable.hashCode() & 0xffffffffL);
                if (log.isDebugEnabled()) {
                    log.debug("ExceptionOccurred: 0x" + Long.toHexString(exception));
                }
                return exception;
            }
        });

        Pointer _ExceptionDescribe = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _ExceptionClear = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                if (log.isDebugEnabled()) {
                    log.debug("ExceptionClear");
                }
                throwable = null;
                return 0;
            }
        });

        Pointer _FatalError = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _PushLocalFrame = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                int capacity = context.getIntArg(1);
                if (log.isDebugEnabled()) {
                    log.debug("PushLocalFrame capacity=" + capacity);
                }
                return JNI_OK;
            }
        });

        Pointer _PopLocalFrame = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer jresult = context.getPointerArg(1);
                if (log.isDebugEnabled()) {
                    log.debug("PopLocalFrame jresult=" + jresult);
                }
                return jresult == null ? 0 : jresult.toIntPeer();
            }
        });

        Pointer _NewGlobalRef = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                if (object == null) {
                    return 0;
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("NewGlobalRef object=" + object + ", dvmObject=" + dvmObject);
                }
                if (verbose) {
                    System.out.printf("JNIEnv->NewGlobalRef(%s) was called from %s%n", dvmObject, context.getLRPointer());
                }
                return addGlobalObject(dvmObject);
            }
        });

        Pointer _DeleteGlobalRef = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                if (log.isDebugEnabled()) {
                    log.debug("DeleteGlobalRef object=" + object);
                }
                ObjRef ref = object == null ? null : globalObjectMap.remove(object.toIntPeer());
                if (ref != null) {
                    ref.obj.onDeleteRef();
                }
                if (verbose) {
                    System.out.printf("JNIEnv->DeleteGlobalRef(%s) was called from %s%n", ref, context.getLRPointer());
                }
                return 0;
            }
        });

        Pointer _DeleteLocalRef = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                if (log.isDebugEnabled()) {
                    log.debug("DeleteLocalRef object=" + object);
                }
                return 0;
            }
        });

        Pointer _IsSameObject = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer ref1 = context.getPointerArg(1);
                UnidbgPointer ref2 = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("IsSameObject ref1=" + ref1 + ", ref2=" + ref2);
                }
                return ref1 == ref2 || ref1.equals(ref2) ? JNI_TRUE : JNI_FALSE;
            }
        });

        Pointer _NewLocalRef = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                if (object == null) {
                    return 0;
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("NewLocalRef object=" + object + ", dvmObject=" + dvmObject + ", class=" + (dvmObject != null ? dvmObject.getObjectType() : null));
                }
                if (verbose) {
                    System.out.printf("JNIEnv->NewLocalRef(%s) was called from %s%n", dvmObject, context.getLRPointer());
                }
                return object.toIntPeer();
            }
        });

        Pointer _EnsureLocalCapacity = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                int capacity = context.getIntArg(1);
                if (log.isDebugEnabled()) {
                    log.debug("EnsureLocalCapacity capacity=" + capacity);
                }
                return 0;
            }
        });

        Pointer _AllocObject = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("AllocObject clazz=" + dvmClass + ", lr=" + context.getLRPointer());
                }
                if (dvmClass == null) {
                    throw new BackendException();
                } else {
                    DvmObject<?> obj = dvmClass.allocObject();
                    if (verbose) {
                        System.out.printf("JNIEnv->AllocObject(%s => %s) was called from %s%n", dvmClass.getClassName(), obj, context.getLRPointer());
                    }
                    return addLocalObject(obj);
                }
            }
        });

        Pointer _NewObject = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("NewObject clazz=" + dvmClass + ", jmethodID=" + jmethodID + ", lr=" + context.getLRPointer());
                }
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VarArg varArg = ArmVarArg.create(emulator, DalvikVM64.this, dvmMethod);
                    DvmObject<?> obj = dvmMethod.newObject(varArg);
                    if (verbose) {
                        System.out.printf("JNIEnv->NewObject(%s, %s(%s) => %s) was called from %s%n", dvmClass, dvmMethod.methodName, varArg.formatArgs(), obj, context.getLRPointer());
                    }
                    return addLocalObject(obj);
                }
            }
        });

        Pointer _NewObjectV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer va_list = context.getPointerArg(3);
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("NewObjectV clazz=" + dvmClass + ", jmethodID=" + jmethodID + ", va_list=" + va_list + ", lr=" + context.getLRPointer());
                }
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList64(emulator, DalvikVM64.this, va_list, dvmMethod);
                    DvmObject<?> obj = dvmMethod.newObjectV(vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->NewObjectV(%s, %s(%s) => %s) was called from %s%n", dvmClass, dvmMethod.methodName, vaList.formatArgs(), obj, context.getLRPointer());
                    }
                    return addLocalObject(obj);
                }
            }
        });

        Pointer _NewObjectA = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetObjectClass = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("GetObjectClass object=" + object + ", dvmObject=" + dvmObject);
                }
                if (dvmObject == null) {
                    throw new BackendException();
                } else {
                    DvmClass dvmClass = dvmObject.getObjectType();
                    return dvmClass.hashCode();
                }
            }
        });

        Pointer _IsInstanceOf = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer clazz = context.getPointerArg(2);
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("IsInstanceOf object=" + object + ", clazz=" + clazz + ", dvmObject=" + dvmObject + ", dvmClass=" + dvmClass);
                }
                if (dvmObject == null || dvmClass == null) {
                    throw new BackendException();
                }
                boolean flag = dvmObject.isInstanceOf(dvmClass);
                return flag ? JNI_TRUE : JNI_FALSE;
            }
        });

        Pointer _GetMethodID = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                Pointer methodName = context.getPointerArg(2);
                Pointer argsPointer = context.getPointerArg(3);
                String name = methodName.getString(0);
                String args = argsPointer.getString(0);
                if (log.isDebugEnabled()) {
                    log.debug("GetMethodID class=" + clazz + ", methodName=" + name + ", args=" + args + ", LR=" + context.getLRPointer());
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                if (dvmClass == null) {
                    throw new BackendException();
                } else {
                    int hash = dvmClass.getMethodID(name, args);
                    if (verbose && hash != 0) {
                        System.out.printf("JNIEnv->GetMethodID(%s.%s%s) => 0x%x was called from %s%n", dvmClass.getClassName(), name, args, hash & 0xffffffffL, context.getLRPointer());
                    }
                    return hash;
                }
            }
        });

        Pointer _CallObjectMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("CallObjectMethod object=" + object + ", jmethodID=" + jmethodID);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VarArg varArg = ArmVarArg.create(emulator, DalvikVM64.this, dvmMethod);
                    DvmObject<?> ret = dvmMethod.callObjectMethod(dvmObject, varArg);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallObjectMethod(%s, %s(%s) => %s) was called from %s%n", dvmObject, dvmMethod.methodName, varArg.formatArgs(), ret, context.getLRPointer());
                    }
                    return addLocalObject(ret);
                }
            }
        });

        Pointer _CallObjectMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer va_list = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallObjectMethodV object=" + object + ", jmethodID=" + jmethodID + ", va_list=" + va_list + ", lr=" + context.getLRPointer());
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException("dvmObject=" + dvmObject + ", dvmClass=" + dvmClass + ", jmethodID=" + jmethodID);
                } else {
                    VaList vaList = new VaList64(emulator, DalvikVM64.this, va_list, dvmMethod);
                    DvmObject<?> obj = dvmMethod.callObjectMethodV(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallObjectMethodV(%s, %s(%s) => %s) was called from %s%n", dvmObject, dvmMethod.methodName, vaList.formatArgs(), obj, context.getLRPointer());
                    }
                    return addLocalObject(obj);
                }
            }
        });

        Pointer _CallObjectMethodA = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer jvalue = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallObjectMethodA object=" + object + ", jmethodID=" + jmethodID + ", jvalue=" + jvalue + ", lr=" + context.getLRPointer());
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException("dvmObject=" + dvmObject + ", dvmClass=" + dvmClass + ", jmethodID=" + jmethodID);
                } else {
                    VaList vaList = new JValueList(DalvikVM64.this, jvalue, dvmMethod);
                    DvmObject<?> obj = dvmMethod.callObjectMethodA(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallObjectMethodA(%s, %s(%s) => %s) was called from %s%n", dvmObject, dvmMethod.methodName, vaList.formatArgs(), obj, context.getLRPointer());
                    }
                    return addLocalObject(obj);
                }
            }
        });

        Pointer _CallBooleanMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("CallBooleanMethod object=" + object + ", jmethodID=" + jmethodID);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VarArg varArg = ArmVarArg.create(emulator, DalvikVM64.this, dvmMethod);
                    boolean ret = dvmMethod.callBooleanMethod(dvmObject, varArg);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallBooleanMethod(%s, %s(%s) => %s) was called from %s%n", dvmObject, dvmMethod.methodName, varArg.formatArgs(), ret, context.getLRPointer());
                    }
                    return ret ? JNI_TRUE : JNI_FALSE;
                }
            }
        });

        Pointer _CallBooleanMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer va_list = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallBooleanMethodV object=" + object + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList64(emulator, DalvikVM64.this, va_list, dvmMethod);
                    boolean ret = dvmMethod.callBooleanMethodV(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallBooleanMethodV(%s, %s(%s) => %s) was called from %s%n", dvmObject, dvmMethod.methodName, vaList.formatArgs(), ret, context.getLRPointer());
                    }
                    return ret ? JNI_TRUE : JNI_FALSE;
                }
            }
        });

        Pointer _CallBooleanMethodA = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer jvalue = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallBooleanMethodA object=" + object + ", jmethodID=" + jmethodID + ", jvalue=" + jvalue);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new JValueList(DalvikVM64.this, jvalue, dvmMethod);
                    boolean ret = dvmMethod.callBooleanMethodA(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallBooleanMethodA(%s, %s(%s) => %s) was called from %s%n", dvmObject, dvmMethod.methodName, vaList.formatArgs(), ret, context.getLRPointer());
                    }
                    return ret ? JNI_TRUE : JNI_FALSE;
                }
            }
        });

        Pointer _CallByteMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallByteMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer va_list = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallByteMethodV object=" + object + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList64(emulator, DalvikVM64.this, va_list, dvmMethod);
                    byte ret = dvmMethod.callByteMethodV(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallByteMethodV(%s, %s(%s) => 0x%x) was called from %s%n", dvmObject, dvmMethod.methodName, vaList.formatArgs(), ret, context.getLRPointer());
                    }
                    return ret;
                }
            }
        });

        Pointer _CallByteMethodA = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallCharMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallCharMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallCharMethodA = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallShortMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallShortMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer va_list = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallShortMethodV object=" + object + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList64(emulator, DalvikVM64.this, va_list, dvmMethod);
                    short ret = dvmMethod.callShortMethodV(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallShortMethodV(%s, %s(%s) => 0x%x) was called from %s%n", dvmObject, dvmMethod.methodName, vaList.formatArgs(), ret, context.getLRPointer());
                    }
                    return ret;
                }
            }
        });

        Pointer _CallShortMethodA = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallIntMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("CallIntMethod object=" + object + ", jmethodID=" + jmethodID);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VarArg varArg = ArmVarArg.create(emulator, DalvikVM64.this, dvmMethod);
                    int ret = dvmMethod.callIntMethod(dvmObject, varArg);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallIntMethod(%s, %s(%s) => 0x%x) was called from %s%n", dvmObject, dvmMethod.methodName, varArg.formatArgs(), ret, context.getLRPointer());
                    }
                    return ret;
                }
            }
        });

        Pointer _CallIntMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer va_list = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallIntMethodV object=" + object + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList64(emulator, DalvikVM64.this, va_list, dvmMethod);
                    int ret = dvmMethod.callIntMethodV(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallIntMethodV(%s, %s(%s) => 0x%x) was called from %s%n", dvmObject, dvmMethod.methodName, vaList.formatArgs(), ret, context.getLRPointer());
                    }
                    return ret;
                }
            }
        });

        Pointer _CallIntMethodA = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer jvalue = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallIntMethodA object=" + object + ", jmethodID=" + jmethodID + ", jvalue=" + jvalue);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new JValueList(DalvikVM64.this, jvalue, dvmMethod);
                    int ret = dvmMethod.callIntMethodA(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallIntMethodA(%s, %s(%s) => 0x%x) was called from %s%n", dvmObject, dvmMethod.methodName, vaList.formatArgs(), ret, context.getLRPointer());
                    }
                    return ret;
                }
            }
        });

        Pointer _CallLongMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("CallLongMethod object=" + object + ", jmethodID=" + jmethodID);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VarArg varArg = ArmVarArg.create(emulator, DalvikVM64.this, dvmMethod);
                    long ret = dvmMethod.callLongMethod(dvmObject, varArg);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallLongMethod(%s, %s(%s) => 0x%xL) was called from %s%n", dvmObject, dvmMethod.methodName, varArg.formatArgs(), ret, context.getLRPointer());
                    }
                    return ret;
                }
            }
        });

        Pointer _CallLongMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer va_list = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallLongMethodV object=" + object + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList64(emulator, DalvikVM64.this, va_list, dvmMethod);
                    long ret = dvmMethod.callLongMethodV(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallLongMethodV(%s, %s(%s) => 0x%xL) was called from %s%n", dvmObject, dvmMethod.methodName, vaList.formatArgs(), ret, context.getLRPointer());
                    }
                    return ret;
                }
            }
        });

        Pointer _CallLongMethodA = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallFloatMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallFloatMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer va_list = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallFloatMethodV object=" + object + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList64(emulator, DalvikVM64.this, va_list, dvmMethod);
                    float ret = dvmMethod.callFloatMethodV(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallFloatMethodV(%s, %s(%s) => %s) was called from %s%n", dvmObject, dvmMethod.methodName, vaList.formatArgs(), ret, context.getLRPointer());
                    }
                    ByteBuffer buffer = ByteBuffer.allocate(16);
                    buffer.order(ByteOrder.LITTLE_ENDIAN);
                    buffer.putFloat(ret);
                    emulator.getBackend().reg_write_vector(Arm64Const.UC_ARM64_REG_Q0, buffer.array());
                    return context.getLongArg(0);
                }
            }
        });

        Pointer _CallFloatMethodA = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallDoubleMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("CallDoubleMethod object=" + object + ", jmethodID=" + jmethodID);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VarArg varArg = ArmVarArg.create(emulator, DalvikVM64.this, dvmMethod);
                    double ret = dvmMethod.callDoubleMethod(dvmObject, varArg);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallDoubleMethod(%s, %s(%s) => %s) was called from %s%n", dvmObject, dvmMethod.methodName, varArg.formatArgs(), ret, context.getLRPointer());
                    }
                    ByteBuffer buffer = ByteBuffer.allocate(16);
                    buffer.order(ByteOrder.LITTLE_ENDIAN);
                    buffer.putDouble(ret);
                    emulator.getBackend().reg_write_vector(Arm64Const.UC_ARM64_REG_Q0, buffer.array());
                    return context.getLongArg(0);
                }
            }
        });

        Pointer _CallDoubleMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallDoubleMethodA = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallVoidMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("CallVoidMethod object=" + object + ", jmethodID=" + jmethodID);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VarArg varArg = ArmVarArg.create(emulator, DalvikVM64.this, dvmMethod);
                    dvmMethod.callVoidMethod(dvmObject, varArg);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallVoidMethod(%s, %s(%s)) was called from %s%n", dvmObject, dvmMethod.methodName, varArg.formatArgs(), context.getLRPointer());
                    }
                    return 0;
                }
            }
        });

        Pointer _CallVoidMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer va_list = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallVoidMethodV object=" + object + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList64(emulator, DalvikVM64.this, va_list, dvmMethod);
                    dvmMethod.callVoidMethodV(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallVoidMethodV(%s, %s(%s)) was called from %s%n", dvmObject, dvmMethod.methodName, vaList.formatArgs(), context.getLRPointer());
                    }
                    return 0;
                }
            }
        });

        Pointer _CallVoidMethodA = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer jvalue = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallVoidMethodA object=" + object + ", jmethodID=" + jmethodID + ", jvalue=" + jvalue);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new JValueList(DalvikVM64.this, jvalue, dvmMethod);
                    dvmMethod.callVoidMethodA(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallVoidMethodA(%s, %s(%s)) was called from %s%n", dvmObject, dvmMethod.methodName, vaList.formatArgs(), context.getLRPointer());
                    }
                    return 0;
                }
            }
        });

        Pointer _CallNonvirtualObjectMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualObjectMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualObjectMethodA = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualBooleanMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualBooleanMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualBooleanMethodA = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer clazz = context.getPointerArg(2);
                UnidbgPointer jmethodID = context.getPointerArg(3);
                UnidbgPointer jvalue = context.getPointerArg(4);
                if (log.isDebugEnabled()) {
                    log.debug("CallNonvirtualBooleanMethodA object=" + object + ", clazz=" + clazz + ", jmethodID=" + jmethodID + ", jvalue=" + jvalue);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new JValueList(DalvikVM64.this, jvalue, dvmMethod);
                    if (dvmMethod.isConstructor()) {
                        throw new IllegalStateException();
                    }
                    boolean ret = dvmMethod.callBooleanMethodA(dvmObject, vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallNonvirtualBooleanMethodA(%s, %s(%s) => %s) was called from %s%n", dvmObject, dvmMethod.methodName, vaList.formatArgs(), ret, context.getLRPointer());
                    }
                    return ret ? JNI_TRUE : JNI_FALSE;
                }
            }
        });

        Pointer _CallNonvirtualByteMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualByteMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualByteMethodA = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualCharMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualCharMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualCharMethodA = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualShortMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualShortMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualShortMethodA = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualIntMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualIntMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualIntMethodA = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualLongMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualLongMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualLongMethodA = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualFloatMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualFloatMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualFloatMethodA = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualDoubleMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualDoubleMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualDoubleMethodA = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualVoidMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallNonvirtualVoidMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer clazz = context.getPointerArg(2);
                UnidbgPointer jmethodID = context.getPointerArg(3);
                UnidbgPointer va_list = context.getPointerArg(4);
                if (log.isDebugEnabled()) {
                    log.debug("CallNonvirtualVoidMethodV object=" + object + ", clazz=" + clazz + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList64(emulator, DalvikVM64.this, va_list, dvmMethod);
                    if (dvmMethod.isConstructor()) {
                        DvmObject<?> obj = dvmMethod.newObjectV(vaList);
                        Objects.requireNonNull(dvmObject).setValue(obj.value);
                    } else {
                        dvmMethod.callVoidMethodV(dvmObject, vaList);
                    }
                    if (verbose) {
                        System.out.printf("JNIEnv->CallNonvirtualVoidMethodV(%s, %s, %s(%s)) was called from %s%n", dvmObject, dvmClass.getClassName(), dvmMethod.methodName, vaList.formatArgs(), context.getLRPointer());
                    }
                    return 0;
                }
            }
        });

        Pointer _CallNonVirtualVoidMethodA = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer clazz = context.getPointerArg(2);
                UnidbgPointer jmethodID = context.getPointerArg(3);
                UnidbgPointer jvalue = context.getPointerArg(4);
                if (log.isDebugEnabled()) {
                    log.debug("CallNonVirtualVoidMethodA object=" + object + ", clazz=" + clazz + ", jmethodID=" + jmethodID + ", jvalue=" + jvalue);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new JValueList(DalvikVM64.this, jvalue, dvmMethod);
                    if (dvmMethod.isConstructor()) {
                        DvmObject<?> obj = dvmMethod.newObjectV(vaList);
                        Objects.requireNonNull(dvmObject).setValue(obj.value);
                    } else {
                        dvmMethod.callVoidMethodA(dvmObject, vaList);
                    }
                    if (verbose) {
                        System.out.printf("JNIEnv->CallNonVirtualVoidMethodA(%s, %s, %s(%s)) was called from %s%n", dvmObject, dvmClass.getClassName(), dvmMethod.methodName, vaList.formatArgs(), context.getLRPointer());
                    }
                    return 0;
                }
            }
        });

        Pointer _GetFieldID = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer fieldName = context.getPointerArg(2);
                Pointer argsPointer = context.getPointerArg(3);
                String name = fieldName.getString(0);
                String args = argsPointer.getString(0);
                if (log.isDebugEnabled()) {
                    log.debug("GetFieldID class=" + clazz + ", fieldName=" + name + ", args=" + args);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                if (dvmClass == null) {
                    throw new BackendException();
                } else {
                    int hash = dvmClass.getFieldID(name, args);
                    if (verbose && hash != 0) {
                        System.out.printf("JNIEnv->GetFieldID(%s.%s %s) => 0x%x was called from %s%n", dvmClass.getClassName(), name, args, hash & 0xffffffffL, context.getLRPointer());
                    }
                    return hash;
                }
            }
        });

        Pointer _GetObjectField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("GetObjectField object=" + object + ", jfieldID=" + jfieldID);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    DvmObject<?> obj = dvmField.getObjectField(dvmObject);
                    if (verbose) {
                        System.out.printf("JNIEnv->GetObjectField(%s, %s %s => %s) was called from %s%n", dvmObject, dvmField.fieldName, dvmField.fieldType, obj, context.getLRPointer());
                    }
                    return addLocalObject(obj);
                }
            }
        });

        Pointer _GetBooleanField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("GetBooleanField object=" + object + ", jfieldID=" + jfieldID);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    int ret = dvmField.getBooleanField(dvmObject);
                    if (verbose) {
                        System.out.printf("JNIEnv->GetBooleanField(%s, %s => %s) was called from %s%n", dvmObject, dvmField.fieldName, ret == JNI_TRUE, context.getLRPointer());
                    }
                    return ret;
                }
            }
        });

        Pointer _GetByteField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetCharField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetShortField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetIntField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("GetIntField object=" + object + ", jfieldID=" + jfieldID);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    int ret = dvmField.getIntField(dvmObject);
                    if (verbose) {
                        System.out.printf("JNIEnv->GetIntField(%s, %s => 0x%x) was called from %s%n", dvmObject, dvmField.fieldName, ret, context.getLRPointer());
                    }
                    return ret;
                }
            }
        });

        Pointer _GetLongField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("GetLongField object=" + object + ", jfieldID=" + jfieldID);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    long ret = dvmField.getLongField(dvmObject);
                    if (verbose) {
                        System.out.printf("JNIEnv->GetLongField(%s, %s => 0x%x) was called from %s%n", dvmObject, dvmField.fieldName, ret, context.getLRPointer());
                    }
                    return ret;
                }
            }
        });

        Pointer _GetFloatField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("GetFloatField object=" + object + ", jfieldID=" + jfieldID);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    float ret = dvmField.getFloatField(dvmObject);
                    if (verbose) {
                        System.out.printf("JNIEnv->GetFloatField(%s, %s => %s) was called from %s%n", dvmObject, dvmField.fieldName, ret, context.getLRPointer());
                    }
                    ByteBuffer buffer = ByteBuffer.allocate(16);
                    buffer.order(ByteOrder.LITTLE_ENDIAN);
                    buffer.putFloat(ret);
                    emulator.getBackend().reg_write_vector(Arm64Const.UC_ARM64_REG_Q0, buffer.array());
                    return context.getLongArg(0);
                }
            }
        });

        Pointer _GetDoubleField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _SetObjectField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                UnidbgPointer value = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("SetObjectField object=" + object + ", jfieldID=" + jfieldID + ", value=" + value);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    DvmObject<?> obj = value == null ? null : getObject(value.toIntPeer());
                    dvmField.setObjectField(dvmObject, obj);
                    if (verbose) {
                        System.out.printf("JNIEnv->SetObjectField(%s, %s %s => %s) was called from %s%n", dvmObject, dvmField.fieldName, dvmField.fieldType, obj, context.getLRPointer());
                    }
                }
                return 0;
            }
        });

        Pointer _SetBooleanField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                int value = context.getIntArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("SetBooleanField object=" + object + ", jfieldID=" + jfieldID + ", value=" + value);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    boolean flag = BaseVM.valueOf(value);
                    dvmField.setBooleanField(dvmObject, flag);
                    if (verbose) {
                        System.out.printf("JNIEnv->SetBooleanField(%s, %s => %s) was called from %s%n", dvmObject, dvmField.fieldName, flag, context.getLRPointer());
                    }
                }
                return 0;
            }
        });

        Pointer _SetByteField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _SetCharField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _SetShortField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _SetIntField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                int value = context.getIntArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("SetIntField object=" + object + ", jfieldID=" + jfieldID + ", value=" + value);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    dvmField.setIntField(dvmObject, value);
                    if (verbose) {
                        System.out.printf("JNIEnv->SetIntField(%s, %s => 0x%x) was called from %s%n", dvmObject, dvmField.fieldName, value, context.getLRPointer());
                    }
                }
                return 0;
            }
        });

        Pointer _SetLongField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                long value = context.getLongArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("SetLongField object=" + object + ", jfieldID=" + jfieldID + ", value=" + value);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    dvmField.setLongField(dvmObject, value);
                    if (verbose) {
                        System.out.printf("JNIEnv->SetLongField(%s, %s => 0x%x) was called from %s%n", dvmObject, dvmField.fieldName, value, context.getLRPointer());
                    }
                }
                return 0;
            }
        });

        Pointer _SetFloatField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                ByteBuffer buffer = ByteBuffer.allocate(16);
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                buffer.put(emulator.getBackend().reg_read_vector(Arm64Const.UC_ARM64_REG_Q0));
                buffer.flip();
                float value = buffer.getFloat();
                if (log.isDebugEnabled()) {
                    log.debug("SetFloatField object=" + object + ", jfieldID=" + jfieldID + ", value=" + value);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    dvmField.setFloatField(dvmObject, value);
                    if (verbose) {
                        System.out.printf("JNIEnv->SetFloatField(%s, %s => %s) was called from %s%n", dvmObject, dvmField.fieldName, value, context.getLRPointer());
                    }
                }
                return 0;
            }
        });

        Pointer _SetDoubleField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                ByteBuffer buffer = ByteBuffer.allocate(16);
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                buffer.put(emulator.getBackend().reg_read_vector(Arm64Const.UC_ARM64_REG_Q0));
                buffer.flip();
                double value = buffer.getDouble();
                if (log.isDebugEnabled()) {
                    log.debug("SetDoubleField object=" + object + ", jfieldID=" + jfieldID + ", value=" + value);
                }
                DvmObject<?> dvmObject = getObject(object.toIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.getObjectType();
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    dvmField.setDoubleField(dvmObject, value);
                    if (verbose) {
                        System.out.printf("JNIEnv->SetDoubleField(%s, %s => %s) was called from %s%n", dvmObject, dvmField.fieldName, value, context.getLRPointer());
                    }
                }
                return 0;
            }
        });

        Pointer _GetStaticMethodID = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                Pointer methodName = context.getPointerArg(2);
                Pointer argsPointer = context.getPointerArg(3);
                String name = methodName.getString(0);
                String args = argsPointer.getString(0);
                if (log.isDebugEnabled()) {
                    log.debug("GetStaticMethodID class=" + clazz + ", methodName=" + name + ", args=" + args + ", LR=" + context.getLRPointer());
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                if (dvmClass == null) {
                    throw new BackendException();
                } else {
                    int hash = dvmClass.getStaticMethodID(name, args);
                    if (verbose && hash != 0) {
                        System.out.printf("JNIEnv->GetStaticMethodID(%s.%s%s) => 0x%x was called from %s%n", dvmClass.getClassName(), name, args, hash & 0xffffffffL, context.getLRPointer());
                    }
                    return hash;
                }
            }
        });

        Pointer _CallStaticObjectMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticObjectMethod clazz=" + clazz + ", jmethodID=" + jmethodID);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VarArg varArg = ArmVarArg.create(emulator, DalvikVM64.this, dvmMethod);
                    DvmObject<?> obj = dvmMethod.callStaticObjectMethod(varArg);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticObjectMethod(%s, %s(%s) => %s) was called from %s%n", dvmClass, dvmMethod.methodName, varArg.formatArgs(), obj, context.getLRPointer());
                    }
                    return addLocalObject(obj);
                }
            }
        });

        Pointer _CallStaticObjectMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer va_list = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticObjectMethodV clazz=" + clazz + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList64(emulator, DalvikVM64.this, va_list, dvmMethod);
                    DvmObject<?> obj = dvmMethod.callStaticObjectMethodV(vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticObjectMethodV(%s, %s(%s) => %s) was called from %s%n", dvmClass, dvmMethod.methodName, vaList.formatArgs(), obj, context.getLRPointer());
                    }
                    return addLocalObject(obj);
                }
            }
        });

        Pointer _CallStaticObjectMethodA = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer jvalue = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticObjectMethodA clazz=" + clazz + ", jmethodID=" + jmethodID + ", jvalue=" + jvalue);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new JValueList(DalvikVM64.this, jvalue, dvmMethod);
                    DvmObject<?> obj = dvmMethod.callStaticObjectMethodA(vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticObjectMethodA(%s, %s(%s) => %s) was called from %s%n", dvmClass, dvmMethod.methodName, vaList.formatArgs(), obj, context.getLRPointer());
                    }
                    return addLocalObject(obj);
                }
            }
        });

        Pointer _CallStaticBooleanMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticBooleanMethod clazz=" + clazz + ", jmethodID=" + jmethodID);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VarArg varArg = ArmVarArg.create(emulator, DalvikVM64.this, dvmMethod);
                    boolean ret = dvmMethod.CallStaticBooleanMethod(varArg);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticBooleanMethod(%s, %s(%s) => %s) was called from %s%n", dvmClass, dvmMethod.methodName, varArg.formatArgs(), ret, context.getLRPointer());
                    }
                    return ret ? JNI_TRUE : JNI_FALSE;
                }
            }
        });

        Pointer _CallStaticBooleanMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer va_list = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticBooleanMethodV clazz=" + clazz + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList64(emulator, DalvikVM64.this, va_list, dvmMethod);
                    boolean ret = dvmMethod.callStaticBooleanMethodV(vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticBooleanMethodV(%s, %s(%s) => %s) was called from %s%n", dvmClass, dvmMethod.methodName, vaList.formatArgs(), ret, context.getLRPointer());
                    }
                    return ret ? JNI_TRUE : JNI_FALSE;
                }
            }
        });

        Pointer _CallStaticBooleanMethodA = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer jvalue = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticBooleanMethodA clazz=" + clazz + ", jmethodID=" + jmethodID + ", jvalue=" + jvalue);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new JValueList(DalvikVM64.this, jvalue, dvmMethod);
                    boolean ret = dvmMethod.callStaticBooleanMethodV(vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticBooleanMethodA(%s, %s(%s) => %s) was called from %s%n", dvmClass, dvmMethod.methodName, vaList.formatArgs(), ret, context.getLRPointer());
                    }
                    return ret ? VM.JNI_TRUE : VM.JNI_FALSE;
                }
            }
        });

        Pointer _CallStaticByteMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallStaticByteMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallStaticByteMethodA = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallStaticCharMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallStaticCharMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallStaticCharMethodA = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallStaticShortMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallStaticShortMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallStaticShortMethodA = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallStaticIntMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticIntMethodV clazz=" + clazz + ", jmethodID=" + jmethodID);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VarArg varArg = ArmVarArg.create(emulator, DalvikVM64.this, dvmMethod);
                    int ret = dvmMethod.callStaticIntMethod(varArg);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticIntMethod(%s, %s(%s) => 0x%x) was called from %s%n", dvmClass, dvmMethod.methodName, varArg.formatArgs(), ret, context.getLRPointer());
                    }
                    return ret;
                }
            }
        });

        Pointer _CallStaticIntMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer va_list = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticIntMethodV clazz=" + clazz + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList64(emulator, DalvikVM64.this, va_list, dvmMethod);
                    int ret = dvmMethod.callStaticIntMethodV(vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticIntMethodV(%s, %s(%s) => 0x%x) was called from %s%n", dvmClass, dvmMethod.methodName, vaList.formatArgs(), ret, context.getLRPointer());
                    }
                    return ret;
                }
            }
        });

        Pointer _CallStaticIntMethodA = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallStaticLongMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticLongMethod clazz=" + clazz + ", jmethodID=" + jmethodID);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VarArg varArg = ArmVarArg.create(emulator, DalvikVM64.this, dvmMethod);
                    long value = dvmMethod.callStaticLongMethod(varArg);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticLongMethod(%s, %s(%s)) was called from %s%n", dvmClass, dvmMethod.methodName, varArg.formatArgs(), context.getLRPointer());
                    }
                    return value;
                }
            }
        });

        Pointer _CallStaticLongMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer va_list = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticLongMethodV clazz=" + clazz + ", jmethodID=" + jmethodID + ", va_list=" + va_list + ", lr=" + context.getLRPointer());
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList64(emulator, DalvikVM64.this, va_list, dvmMethod);
                    long ret = dvmMethod.callStaticLongMethodV(vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticLongMethodV(%s, %s(%s) => 0x%xL) was called from %s%n", dvmClass, dvmMethod.methodName, vaList.formatArgs(), ret, context.getLRPointer());
                    }
                    return ret;
                }
            }
        });

        Pointer _CallStaticLongMethodA = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallStaticFloatMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticFloatMethod clazz=" + clazz + ", jmethodID=" + jmethodID);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VarArg varArg = ArmVarArg.create(emulator, DalvikVM64.this, dvmMethod);
                    float ret = dvmMethod.callStaticFloatMethod(varArg);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticFloatMethod(%s, %s(%s) => %s) was called from %s%n", dvmClass, dvmMethod.methodName, varArg.formatArgs(), ret, context.getLRPointer());
                    }
                    ByteBuffer buffer = ByteBuffer.allocate(16);
                    buffer.order(ByteOrder.LITTLE_ENDIAN);
                    buffer.putFloat(ret);
                    emulator.getBackend().reg_write_vector(Arm64Const.UC_ARM64_REG_Q0, buffer.array());
                    return context.getLongArg(0);
                }
            }
        });

        Pointer _CallStaticFloatMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallStaticFloatMethodA = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallStaticDoubleMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticDoubleMethod clazz=" + clazz + ", jmethodID=" + jmethodID);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VarArg varArg = ArmVarArg.create(emulator, DalvikVM64.this, dvmMethod);
                    double ret = dvmMethod.callStaticDoubleMethod(varArg);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticDoubleMethod(%s, %s(%s) => %s) was called from %s%n", dvmClass, dvmMethod.methodName, varArg.formatArgs(), ret, context.getLRPointer());
                    }
                    ByteBuffer buffer = ByteBuffer.allocate(16);
                    buffer.order(ByteOrder.LITTLE_ENDIAN);
                    buffer.putDouble(ret);
                    emulator.getBackend().reg_write_vector(Arm64Const.UC_ARM64_REG_Q0, buffer.array());
                    return context.getLongArg(0);
                }
            }
        });

        Pointer _CallStaticDoubleMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallStaticDoubleMethodA = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _CallStaticVoidMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticVoidMethod clazz=" + clazz + ", jmethodID=" + jmethodID);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VarArg varArg = ArmVarArg.create(emulator, DalvikVM64.this, dvmMethod);
                    dvmMethod.callStaticVoidMethod(varArg);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticVoidMethod(%s, %s(%s)) was called from %s%n", dvmClass, dvmMethod.methodName, varArg.formatArgs(), context.getLRPointer());
                    }
                    return 0;
                }
            }
        });

        Pointer _CallStaticVoidMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer va_list = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticVoidMethodV clazz=" + clazz + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new VaList64(emulator, DalvikVM64.this, va_list, dvmMethod);
                    dvmMethod.callStaticVoidMethodV(vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticVoidMethodV(%s, %s(%s)) was called from %s%n", dvmClass, dvmMethod.methodName, vaList.formatArgs(), context.getLRPointer());
                    }
                    return 0;
                }
            }
        });

        Pointer _CallStaticVoidMethodA = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jmethodID = context.getPointerArg(2);
                UnidbgPointer jvalue = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticVoidMethodA clazz=" + clazz + ", jmethodID=" + jmethodID + ", jvalue=" + jvalue);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toIntPeer());
                if (dvmMethod == null) {
                    throw new BackendException();
                } else {
                    VaList vaList = new JValueList(DalvikVM64.this, jvalue, dvmMethod);
                    dvmMethod.callStaticVoidMethodA(vaList);
                    if (verbose) {
                        System.out.printf("JNIEnv->CallStaticVoidMethodA(%s, %s(%s)) was called from %s%n", dvmClass, dvmMethod.methodName, vaList.formatArgs(), context.getLRPointer());
                    }
                    return 0;
                }
            }
        });

        Pointer _GetStaticFieldID = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer fieldName = context.getPointerArg(2);
                Pointer argsPointer = context.getPointerArg(3);
                String name = fieldName.getString(0);
                String args = argsPointer.getString(0);
                if (log.isDebugEnabled()) {
                    log.debug("GetStaticFieldID class=" + clazz + ", fieldName=" + name + ", args=" + args);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                if (dvmClass == null) {
                    throw new BackendException();
                } else {
                    int hash = dvmClass.getStaticFieldID(name, args);
                    if (verbose && hash != 0) {
                        System.out.printf("JNIEnv->GetStaticFieldID(%s.%s%s) => 0x%x was called from %s%n", dvmClass.getClassName(), name, args, hash & 0xffffffffL, context.getLRPointer());
                    }
                    return hash;
                }
            }
        });

        Pointer _GetStaticObjectField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("GetStaticObjectField clazz=" + clazz + ", jfieldID=" + jfieldID);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmField dvmField = dvmClass == null ? null : dvmClass.getStaticField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    DvmObject<?> obj = dvmField.getStaticObjectField();
                    if (verbose) {
                        System.out.printf("JNIEnv->GetStaticObjectField(%s, %s %s => %s) was called from %s%n", dvmClass, dvmField.fieldName, dvmField.fieldType, obj, context.getLRPointer());
                    }
                    return addLocalObject(obj);
                }
            }
        });

        Pointer _GetStaticBooleanField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("GetStaticBooleanField clazz=" + clazz + ", jfieldID=" + jfieldID);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmField dvmField = dvmClass == null ? null : dvmClass.getStaticField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    boolean ret = dvmField.getStaticBooleanField();
                    if (verbose) {
                        System.out.printf("JNIEnv->GetStaticBooleanField(%s, %s => %s) was called from %s%n", dvmClass, dvmField.fieldName, ret, context.getLRPointer());
                    }
                    return ret ? VM.JNI_TRUE : VM.JNI_FALSE;
                }
            }
        });

        Pointer _GetStaticByteField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("GetStaticByteField clazz=" + clazz + ", jfieldID=" + jfieldID);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmField dvmField = dvmClass == null ? null : dvmClass.getStaticField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    byte ret = dvmField.getStaticByteField();
                    if (verbose) {
                        System.out.printf("JNIEnv->GetStaticByteField(%s, %s => %s) was called from %s%n", dvmClass, dvmField.fieldName, ret, context.getLRPointer());
                    }
                    return ret;
                }
            }
        });

        Pointer _GetStaticCharField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetStaticShortField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetStaticIntField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("GetStaticIntField clazz=" + clazz + ", jfieldID=" + jfieldID);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmField dvmField = dvmClass == null ? null : dvmClass.getStaticField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    int ret = dvmField.getStaticIntField();
                    if (verbose) {
                        System.out.printf("JNIEnv->GetStaticIntField(%s, %s => 0x%x) was called from %s%n", dvmClass, dvmField.fieldName, ret, context.getLRPointer());
                    }
                    return ret;
                }
            }
        });

        Pointer _GetStaticLongField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                Arm64RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getXPointer(1);
                UnidbgPointer jfieldID = context.getXPointer(2);
                if (log.isDebugEnabled()) {
                    log.debug("GetStaticLongField clazz=" + clazz + ", jfieldID=" + jfieldID);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmField dvmField = dvmClass == null ? null : dvmClass.getStaticField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException();
                } else {
                    long ret = dvmField.getStaticLongField();
                    if (verbose) {
                        System.out.printf("JNIEnv->GetStaticLongField(%s, %s => 0x%x) was called from %s%n", dvmClass, dvmField.fieldName, ret, context.getLRPointer());
                    }
                    return ret;
                }
            }
        });

        Pointer _GetStaticFloatField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetStaticDoubleField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _SetStaticObjectField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _SetStaticBooleanField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _SetStaticByteField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _SetStaticCharField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _SetStaticShortField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _SetStaticIntField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                int value = context.getIntArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("SetStaticIntField clazz=" + clazz + ", jfieldID=" + jfieldID + ", value=" + value);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmField dvmField = dvmClass == null ? null : dvmClass.getStaticField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException("dvmClass=" + dvmClass);
                } else {
                    if (verbose) {
                        System.out.printf("JNIEnv->SetStaticIntField(%s, %s, 0x%x) was called from %s%n", dvmClass, dvmField.fieldName, value, context.getLRPointer());
                    }
                    dvmField.setStaticIntField(value);
                }
                return 0;
            }
        });

        Pointer _SetStaticLongField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                long value = context.getLongArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("SetStaticLongField clazz=" + clazz + ", jfieldID=" + jfieldID + ", value=" + value);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmField dvmField = dvmClass == null ? null : dvmClass.getStaticField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException("dvmClass=" + dvmClass);
                } else {
                    if (verbose) {
                        System.out.printf("JNIEnv->SetStaticLongField(%s, %s, 0x%x) was called from %s%n", dvmClass, dvmField.fieldName, value, context.getLRPointer());
                    }
                    dvmField.setStaticLongField(value);
                }
                return 0;
            }
        });

        Pointer _GetStringUTFLength = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                DvmObject<?> string = getObject(object.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("GetStringUTFLength string=" + string + ", lr=" + context.getLRPointer());
                }
                String value = (String) Objects.requireNonNull(string).getValue();
                if (verbose) {
                    System.out.printf("JNIEnv->GetStringUTFLength(%s) was called from %s%n", string, context.getLRPointer());
                }
                byte[] data = value.getBytes(StandardCharsets.UTF_8);
                return data.length;
            }
        });

        Pointer _GetStringUTFChars = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer isCopy = context.getPointerArg(2);
                StringObject string = getObject(object.toIntPeer());
                if (isCopy != null) {
                    isCopy.setInt(0, JNI_TRUE);
                }
                String value = Objects.requireNonNull(string).getValue();
                if (verbose) {
                    System.out.printf("JNIEnv->GetStringUtfChars(%s) was called from %s%n", string, context.getLRPointer());
                }
                byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
                if (log.isDebugEnabled()) {
                    log.debug("GetStringUTFChars string=" + string + ", isCopy=" + isCopy + ", value=" + value + ", lr=" + context.getLRPointer());
                }
                byte[] data = Arrays.copyOf(bytes, bytes.length + 1);
                UnidbgPointer pointer = string.allocateMemoryBlock(emulator, data.length);
                pointer.write(0, data, 0, data.length);
                return pointer.toIntPeer();
            }
        });

        Pointer _ReleaseStringUTFChars = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                UnidbgPointer pointer = context.getPointerArg(2);
                StringObject string = getObject(object.toIntPeer());
                if (verbose) {
                    System.out.printf("JNIEnv->ReleaseStringUTFChars(%s) was called from %s%n", string, context.getLRPointer());
                }
                if (log.isDebugEnabled()) {
                    log.debug("ReleaseStringUTFChars string=" + string + ", pointer=" + pointer + ", lr=" + context.getLRPointer());
                }
                Objects.requireNonNull(string).freeMemoryBlock(pointer);
                return 0;
            }
        });

        Pointer _GetArrayLength = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer pointer = context.getPointerArg(1);
                Array<?> array = Objects.requireNonNull((Array<?>) getObject(pointer.toIntPeer()));
                if (log.isDebugEnabled()) {
                    log.debug("GetArrayLength array=" + array);
                }
                if (verbose) {
                    System.out.printf("JNIEnv->GetArrayLength(%s => %s) was called from %s%n", array, array.length(), context.getLRPointer());
                }
                return array.length();
            }
        });

        Pointer _NewObjectArray = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                int size = context.getIntArg(1);
                UnidbgPointer elementClass = context.getPointerArg(2);
                UnidbgPointer initialElement = context.getPointerArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("NewObjectArray size=" + size + ", elementClass=" + elementClass + ", initialElement=" + initialElement);
                }
                DvmClass dvmClass = classMap.get(elementClass.toIntPeer());
                if (dvmClass == null) {
                    throw new BackendException("elementClass=" + elementClass);
                }

                DvmObject<?> obj = size == 0 ? null : initialElement == null ? null : getObject(initialElement.toIntPeer());
                DvmObject<?>[] array = new DvmObject[size];
                for (int i = 0; i < size; i++) {
                    array[i] = obj;
                }

                return addLocalObject(new ArrayObject(array));
            }
        });

        Pointer _GetObjectArrayElement = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                int index = context.getIntArg(2);
                ArrayObject array = getObject(object.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("GetObjectArrayElement array=" + array + ", index=" + index);
                }
                DvmObject<?> obj = Objects.requireNonNull(array).getValue()[index];
                if (verbose) {
                    System.out.printf("JNIEnv->GetObjectArrayElement(%s, %d) => %s was called from %s%n", array, index, obj, context.getLRPointer());
                }
                return addLocalObject(obj);
            }
        });

        Pointer _SetObjectArrayElement = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                int index = context.getIntArg(2);
                UnidbgPointer element = context.getPointerArg(3);
                ArrayObject array = getObject(object.toIntPeer());
                DvmObject<?> obj = element == null ? null : getObject(element.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("setObjectArrayElement array=" + array + ", index=" + index + ", obj=" + obj);
                }
                DvmObject<?>[] objs = Objects.requireNonNull(array).getValue();
                objs[index] = obj;
                return 0;
            }
        });

        Pointer _NewBooleanArray = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _NewByteArray = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                int size = context.getIntArg(1);
                if (log.isDebugEnabled()) {
                    log.debug("NewByteArray size=" + size);
                }
                if (verbose) {
                    System.out.printf("JNIEnv->NewByteArray(%d) was called from %s%n", size, context.getLRPointer());
                }
                return addLocalObject(new ByteArray(DalvikVM64.this, new byte[size]));
            }
        });

        Pointer _NewCharArray = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _NewShortArray = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _NewIntArray = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                int size = context.getIntArg(1);
                if (log.isDebugEnabled()) {
                    log.debug("NewIntArray size=" + size);
                }
                if (verbose) {
                    System.out.printf("JNIEnv->NewIntArray(%d) was called from %s%n", size, context.getLRPointer());
                }
                return addLocalObject(new IntArray(DalvikVM64.this, new int[size]));
            }
        });

        Pointer _NewLongArray = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _NewFloatArray = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                int size = context.getIntArg(1);
                if (log.isDebugEnabled()) {
                    log.debug("NewFloatArray size=" + size);
                }
                if (verbose) {
                    System.out.printf("JNIEnv->NewFloatArray(%d) was called from %s%n", size, context.getLRPointer());
                }
                return addLocalObject(new FloatArray(DalvikVM64.this, new float[size]));
            }
        });

        Pointer _NewDoubleArray = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                int size = context.getIntArg(1);
                if (log.isDebugEnabled()) {
                    log.debug("_NewDoubleArray size=" + size);
                }
                if (verbose) {
                    System.out.printf("JNIEnv->NewDoubleArray(%d) was called from %s%n", size, context.getLRPointer());
                }
                return addLocalObject(new DoubleArray(DalvikVM64.this, new double[size]));
            }
        });

        Pointer _GetBooleanArrayElements = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetByteArrayElements = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer arrayPointer = context.getPointerArg(1);
                Pointer isCopy = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("GetByteArrayElements arrayPointer=" + arrayPointer + ", isCopy=" + isCopy);
                }
                if (isCopy != null) {
                    isCopy.setInt(0, JNI_TRUE);
                }
                ByteArray array = getObject(arrayPointer.toIntPeer());
                return Objects.requireNonNull(array)._GetArrayCritical(emulator, isCopy).peer;
            }
        });

        Pointer _GetCharArrayElements = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetShortArrayElements = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetIntArrayElements = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                Pointer isCopy = context.getPointerArg(2);
                IntArray array = getObject(object.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("GetIntArrayElements array=" + array + ", isCopy=" + isCopy);
                }
                return Objects.requireNonNull(array)._GetArrayCritical(emulator, isCopy).peer;
            }
        });

        Pointer _SetStaticFloatField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                ByteBuffer buffer = ByteBuffer.allocate(16);
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                buffer.put(emulator.getBackend().reg_read_vector(Arm64Const.UC_ARM64_REG_Q0));
                buffer.flip();
                float value = buffer.getFloat();
                if (log.isDebugEnabled()) {
                    log.debug("SetStaticFloatField clazz=" + clazz + ", jfieldID=" + jfieldID + ", value=" + value);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmField dvmField = dvmClass == null ? null : dvmClass.getStaticField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException("dvmClass=" + dvmClass);
                } else {
                    dvmField.setStaticFloatField(value);
                    if (verbose) {
                        System.out.printf("JNIEnv->SetStaticFloatField(%s, %s, %s) was called from %s%n", dvmClass, dvmField.fieldName, value, context.getLRPointer());
                    }
                }
                return 0;
            }
        });

        Pointer _SetStaticDoubleField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                UnidbgPointer jfieldID = context.getPointerArg(2);
                ByteBuffer buffer = ByteBuffer.allocate(16);
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                buffer.put(emulator.getBackend().reg_read_vector(Arm64Const.UC_ARM64_REG_Q0));
                buffer.flip();
                double value = buffer.getDouble();
                if (log.isDebugEnabled()) {
                    log.debug("SetStaticDoubleField clazz=" + clazz + ", jfieldID=" + jfieldID + ", value=" + value);
                }
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                DvmField dvmField = dvmClass == null ? null : dvmClass.getStaticField(jfieldID.toIntPeer());
                if (dvmField == null) {
                    throw new BackendException("dvmClass=" + dvmClass);
                } else {
                    dvmField.setStaticDoubleField(value);
                    if (verbose) {
                        System.out.printf("JNIEnv->SetStaticDoubleField(%s, %s, %s) was called from %s%n", dvmClass, dvmField.fieldName, value, context.getLRPointer());
                    }
                }
                return 0;
            }
        });

        Pointer _NewString = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetStringLength = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                DvmObject<?> string = getObject(object.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("GetStringLength string=" + string + ", lr=" + context.getLRPointer());
                }
                String value = (String) Objects.requireNonNull(string).getValue();
                return value.length();
            }
        });

        Pointer _GetStringChars = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                Pointer isCopy = context.getPointerArg(2);
                StringObject string = getObject(object.toIntPeer());
                if (isCopy != null) {
                    isCopy.setInt(0, JNI_TRUE);
                }
                String value = Objects.requireNonNull(string).getValue();
                byte[] bytes = new byte[value.length() * 2];
                ByteBuffer buffer = ByteBuffer.wrap(bytes);
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                for (char c : value.toCharArray()) {
                    buffer.putChar(c);
                }
                if (log.isDebugEnabled()) {
                    log.debug("GetStringUTFChars string=" + string + ", isCopy=" + isCopy + ", value=" + value + ", lr=" + context.getLRPointer());
                }
                if (verbose) {
                    System.out.printf("JNIEnv->GetStringUTFChars(\"%s\") was called from %s%n", string, context.getLRPointer());
                }
                byte[] data = Arrays.copyOf(bytes, bytes.length + 1);
                UnidbgPointer pointer = string.allocateMemoryBlock(emulator, data.length);
                pointer.write(0, data, 0, data.length);
                return pointer.toIntPeer();
            }
        });

        Pointer _ReleaseStringChars = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                Pointer pointer = context.getPointerArg(2);
                StringObject string = getObject(object.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("ReleaseStringChars string=" + string + ", pointer=" + pointer + ", lr=" + context.getLRPointer());
                }
                Objects.requireNonNull(string).freeMemoryBlock(pointer);
                return 0;
            }
        });

        Pointer _NewStringUTF = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer bytes = context.getPointerArg(1);
                if (bytes == null) {
                    return VM.JNI_NULL;
                }

                String string = bytes.getString(0);
                if (log.isDebugEnabled()) {
                    log.debug("NewStringUTF bytes=" + bytes + ", string=" + string);
                }
                if (verbose) {
                    System.out.printf("JNIEnv->NewStringUTF(\"%s\") was called from %s%n", string, context.getLRPointer());
                }
                return addLocalObject(new StringObject(DalvikVM64.this, string));
            }
        });

        Pointer _GetLongArrayElements = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetFloatArrayElements = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                Pointer isCopy = context.getPointerArg(2);
                FloatArray array = getObject(object.toIntPeer());
                return Objects.requireNonNull(array)._GetArrayCritical(emulator, isCopy).peer;
            }
        });

        Pointer _GetDoubleArrayElements = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _ReleaseBooleanArrayElements = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _ReleaseByteArrayElements = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer arrayPointer = context.getPointerArg(1);
                Pointer pointer = context.getPointerArg(2);
                int mode = context.getIntArg(3);
                if (log.isDebugEnabled()) {
                    log.debug("ReleaseByteArrayElements arrayPointer=" + arrayPointer + ", pointer=" + pointer + ", mode=" + mode);
                }
                ByteArray array = getObject(arrayPointer.toIntPeer());
                Objects.requireNonNull(array)._ReleaseArrayCritical(pointer, mode);
                return 0;
            }
        });

        Pointer _ReleaseCharArrayElements = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _ReleaseShortArrayElements = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _ReleaseIntArrayElements = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                Pointer pointer = context.getPointerArg(2);
                int mode = context.getIntArg(3);
                IntArray array = getObject(object.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("ReleaseIntArrayElements array=" + array + ", pointer=" + pointer + ", mode=" + mode);
                }
                Objects.requireNonNull(array)._ReleaseArrayCritical(pointer, mode);
                return 0;
            }
        });

        Pointer _ReleaseLongArrayElements = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _ReleaseFloatArrayElements = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                Pointer pointer = context.getPointerArg(2);
                int mode = context.getIntArg(3);
                FloatArray array = getObject(object.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("ReleaseByteArrayElements array=" + array + ", pointer=" + pointer + ", mode=" + mode);
                }
                Objects.requireNonNull(array)._ReleaseArrayCritical(pointer, mode);
                return 0;
            }
        });

        Pointer _ReleaseDoubleArrayElements = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetBooleanArrayRegion = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetByteArrayRegion = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                int start = context.getIntArg(2);
                int length = context.getIntArg(3);
                Pointer buf = context.getPointerArg(4);
                ByteArray array = getObject(object.toIntPeer());
                if (verbose) {
                    System.out.printf("JNIEnv->GetByteArrayRegion(%s, %d, %d, %s) was called from %s%n", array, start, length, buf, context.getLRPointer());
                }
                byte[] data = Arrays.copyOfRange(Objects.requireNonNull(array).value, start, start + length);
                if (log.isDebugEnabled()) {
                    Inspector.inspect(data, "GetByteArrayRegion array=" + array + ", start=" + start + ", length=" + length + ", buf=" + buf);
                }
                buf.write(0, data, 0, data.length);
                return 0;
            }
        });

        Pointer _GetCharArrayRegion = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetShortArrayRegion = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                int start = context.getIntArg(2);
                int length = context.getIntArg(3);
                Pointer buf = context.getPointerArg(4);
                ShortArray array = getObject(object.toIntPeer());
                if (verbose) {
                    System.out.printf("JNIEnv->GetShortArrayRegion(%s, %d, %d, %s) was called from %s%n", array, start, length, buf, context.getLRPointer());
                }
                short[] data = Arrays.copyOfRange(Objects.requireNonNull(array).value, start, start + length);
                if (log.isDebugEnabled()) {
                    log.debug("GetShortArrayRegion array=" + array + ", start=" + start + ", length=" + length + ", buf=" + buf);
                }
                buf.write(0, data, 0, data.length);
                return 0;
            }
        });

        Pointer _GetIntArrayRegion = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetLongArrayRegion = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetFloatArrayRegion = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetDoubleArrayRegion = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                int start = context.getIntArg(2);
                int length = context.getIntArg(3);
                Pointer buf = context.getPointerArg(4);
                DoubleArray array = getObject(object.toIntPeer());
                if (verbose) {
                    System.out.printf("JNIEnv->GetDoubleArrayRegion(%s, %d, %d, %s) was called from %s%n", array, start, length, buf, context.getLRPointer());
                }
                double[] data = Arrays.copyOfRange(Objects.requireNonNull(array).value, start, start + length);
                if (log.isDebugEnabled()) {
                    log.debug("GetDoubleArrayRegion array=" + array + ", start=" + start + ", length=" + length + ", buf=" + buf);
                }
                buf.write(0, data, 0, data.length);
                return 0;
            }
        });

        Pointer _SetBooleanArrayRegion = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _SetByteArrayRegion = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                int start = context.getIntArg(2);
                int length = context.getIntArg(3);
                Pointer buf = context.getPointerArg(4);
                ByteArray array = getObject(object.toIntPeer());
                if (verbose) {
                    System.out.printf("JNIEnv->SetByteArrayRegion(%s, %d, %d, %s) was called from %s%n", array, start, length, buf, context.getLRPointer());
                }
                byte[] data = buf.getByteArray(0, length);
                if (log.isDebugEnabled()) {
                    if (data.length > 1024) {
                        Inspector.inspect(Arrays.copyOf(data, 1024), "SetByteArrayRegion array=" + array + ", start=" + start + ", length=" + length + ", buf=" + buf);
                    } else {
                        Inspector.inspect(data, "SetByteArrayRegion array=" + array + ", start=" + start + ", length=" + length + ", buf=" + buf);
                    }
                }
                Objects.requireNonNull(array).setData(start, data);
                return 0;
            }
        });

        Pointer _SetCharArrayRegion = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _SetShortArrayRegion = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _SetIntArrayRegion = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                int start = context.getIntArg(2);
                int length = context.getIntArg(3);
                Pointer buf = context.getPointerArg(4);
                IntArray array = getObject(object.toIntPeer());
                int[] data = buf.getIntArray(0, length);
                if (log.isDebugEnabled()) {
                    log.debug("SetIntArrayRegion array=" + array + ", start=" + start + ", length=" + length + ", buf=" + buf);
                }
                Objects.requireNonNull(array).setData(start, data);
                return 0;
            }
        });

        Pointer _SetLongArrayRegion = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _SetFloatArrayRegion = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                int start = context.getIntArg(2);
                int length = context.getIntArg(3);
                Pointer buf = context.getPointerArg(4);
                FloatArray array = getObject(object.toIntPeer());
                float[] data = buf.getFloatArray(0, length);
                if (log.isDebugEnabled()) {
                    log.debug("SetIntArrayRegion array=" + array + ", start=" + start + ", length=" + length + ", buf=" + buf);
                }
                Objects.requireNonNull(array).setData(start, data);
                return 0;
            }
        });

        Pointer _SetDoubleArrayRegion = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                int start = context.getIntArg(2);
                int length = context.getIntArg(3);
                Pointer buf = context.getPointerArg(4);
                DoubleArray array = getObject(object.toIntPeer());
                double[] data = buf.getDoubleArray(0, length);
                if (log.isDebugEnabled()) {
                    log.debug("SetDoubleArrayRegion array=" + array + ", start=" + start + ", length=" + length + ", buf=" + buf);
                }
                Objects.requireNonNull(array).setData(start, data);
                return 0;
            }
        });

        Pointer _RegisterNatives = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer clazz = context.getPointerArg(1);
                Pointer methods = context.getPointerArg(2);
                int nMethods = context.getIntArg(3);
                DvmClass dvmClass = classMap.get(clazz.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("RegisterNatives dvmClass=" + dvmClass + ", methods=" + methods + ", nMethods=" + nMethods);
                }
                if (verbose) {
                    System.out.printf("JNIEnv->RegisterNatives(%s, %s, %d) was called from %s%n", dvmClass.getClassName(), methods, nMethods, context.getLRPointer());
                }
                for (int i = 0; i < nMethods; i++) {
                    Pointer method = methods.share((long) i * emulator.getPointerSize() * 3);
                    Pointer name = method.getPointer(0);
                    Pointer signature = method.getPointer(emulator.getPointerSize());
                    Pointer fnPtr = method.getPointer(emulator.getPointerSize() * 2L);
                    String methodName = name.getString(0);
                    String signatureValue = signature.getString(0);
                    if (log.isDebugEnabled()) {
                        log.debug("RegisterNatives dvmClass=" + dvmClass + ", name=" + methodName + ", signature=" + signatureValue + ", fnPtr=" + fnPtr);
                    }
                    dvmClass.nativesMap.put(methodName + signatureValue, (UnidbgPointer) fnPtr);

                    if (verbose) {
                        System.out.printf("RegisterNative(%s, %s%s, %s)%n", dvmClass.getClassName(), methodName, signatureValue, fnPtr);
                    }
                }
                return JNI_OK;
            }
        });

        Pointer _UnregisterNatives = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _MonitorEnter = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                Pointer env = context.getPointerArg(0);
                DvmObject<?> obj = getObject(context.getPointerArg(1).toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("MonitorEnter env=" + env + ", obj=" + obj);
                }
                return 0;
            }
        });

        Pointer _MonitorExit = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                Pointer env = context.getPointerArg(0);
                DvmObject<?> obj = getObject(context.getPointerArg(1).toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("MonitorExit env=" + env + ", obj=" + obj);
                }
                return 0;
            }
        });

        Pointer _GetJavaVM = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer vm = context.getPointerArg(1);
                if (log.isDebugEnabled()) {
                    log.debug("GetJavaVM vm=" + vm);
                }
                vm.setPointer(0, _JavaVM);
                return JNI_OK;
            }
        });

        Pointer _GetStringRegion = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                int start = context.getIntArg(2);
                int length = context.getIntArg(3);
                Pointer buf = context.getPointerArg(4);

                StringObject string = getObject(object.toIntPeer());
                String value = Objects.requireNonNull(string).getValue();
                if (verbose) {
                    System.out.printf("JNIEnv->GetStringRegion(%s) was called from %s%n", string, context.getLRPointer());
                }
                byte[] bytes = new byte[value.length() * 2];
                ByteBuffer buffer = ByteBuffer.wrap(bytes);
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                for (char c : value.toCharArray()) {
                    buffer.putChar(c);
                }
                if (log.isDebugEnabled()) {
                    log.debug("GetStringRegion string=" + string + ", value=" + value + ", start=" + start +
                            ", length=" + length + ", buf" + buf +", lr=" + context.getLRPointer());
                }
                byte[] data = Arrays.copyOfRange(bytes, start, start+length+1);
                buf.write(0, data, 0, data.length);
                return JNI_OK;
            }
        });

        Pointer _GetStringUTFRegion = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                int start = context.getIntArg(2);
                int length = context.getIntArg(3);
                Pointer buf = context.getPointerArg(4);

                StringObject string = getObject(object.toIntPeer());
                String value = Objects.requireNonNull(string).getValue();
                if (verbose) {
                    System.out.printf("JNIEnv->GetStringUTFRegion(%s) was called from %s%n", string, context.getLRPointer());
                }
                byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
                if (log.isDebugEnabled()) {
                    log.debug("GetStringUTFRegion string=" + string + ", value=" + value + ", start=" + start +
                            ", length=" + length + ", buf" + buf +", lr=" + context.getLRPointer());
                }
                byte[] data = Arrays.copyOfRange(bytes, start, start+length+1);
                buf.write(0, data, 0, data.length);
                return JNI_OK;
            }
        });

        Pointer _GetPrimitiveArrayCritical = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                Pointer isCopy = context.getPointerArg(2);
                PrimitiveArray<?> array = getObject(object.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("GetPrimitiveArrayCritical array=" + array + ", isCopy=" + isCopy);
                }
                return Objects.requireNonNull(array)._GetArrayCritical(emulator, isCopy).peer;
            }
        });

        Pointer _ReleasePrimitiveArrayCritical = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                Pointer pointer = context.getPointerArg(2);
                int mode = context.getIntArg(3);
                PrimitiveArray<?> array = getObject(object.toIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("ReleasePrimitiveArrayCritical array=" + array + ", pointer=" + pointer + ", mode=" + mode);
                }
                Objects.requireNonNull(array)._ReleaseArrayCritical(pointer, mode);
                return 0;
            }
        });

        Pointer _GetStringCritical = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _ReleaseStringCritical = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _NewWeakGlobalRef = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                if (object == null) {
                    return 0;
                }
                DvmObject<?> dvmObject = Objects.requireNonNull(getObject(object.toIntPeer()));
                if (log.isDebugEnabled()) {
                    log.debug("NewWeakGlobalRef object=" + object + ", dvmObject=" + dvmObject + ", class=" + dvmObject.getClass());
                }
                return addObject(dvmObject, true, true);
            }
        });

        Pointer _DeleteWeakGlobalRef = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _ExceptionCheck = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                if (log.isDebugEnabled()) {
                    log.debug("ExceptionCheck throwable=" + throwable);
                }
                return throwable == null ? JNI_FALSE : JNI_TRUE;
            }
        });

        Pointer _NewDirectByteBuffer = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetDirectBufferAddress = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetDirectBufferCapacity = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        Pointer _GetObjectRefType = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                UnidbgPointer object = context.getPointerArg(1);
                if (object == null) {
                    return JNIInvalidRefType;
                }
                int hash = object.toIntPeer();
                ObjRef dvmLocalObject = localObjectMap.get(object.toIntPeer());
                ObjRef dvmGlobalObject;
                if (globalObjectMap.containsKey(hash)) {
                    dvmGlobalObject = globalObjectMap.get(hash);
                } else if (weakGlobalObjectMap.containsKey(hash)) {
                    dvmGlobalObject = weakGlobalObjectMap.get(hash);
                } else {
                    dvmGlobalObject = null;
                }
                if (log.isDebugEnabled()) {
                    log.debug("GetObjectRefType object=" + object + ", dvmGlobalObject=" + dvmGlobalObject + ", dvmLocalObject=" + dvmLocalObject);
                }
                if (dvmGlobalObject != null) {
                    return dvmGlobalObject.weak ? JNIWeakGlobalRefType : JNIGlobalRefType;
                } else if(dvmLocalObject != null) {
                    return JNILocalRefType;
                } else {
                    return JNIInvalidRefType;
                }
            }
        });

        Pointer _GetModule = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                throw new UnsupportedOperationException();
            }
        });

        final int last = 0x748;
        final UnidbgPointer impl = svcMemory.allocate(last + 8, "JNIEnv.impl");
        for (int i = 0; i <= last; i += 8) {
            impl.setLong(i, i);
        }
        impl.setPointer(0x20, _GetVersion);
        impl.setPointer(0x28, _DefineClass);
        impl.setPointer(0x30, _FindClass);
        impl.setPointer(0x38, _FromReflectedMethod);
        impl.setPointer(0x40, _FromReflectedField);
        impl.setPointer(0x48, _ToReflectedMethod);
        impl.setPointer(0x50, _GetSuperclass);
        impl.setPointer(0x58, _IsAssignableFrom);
        impl.setPointer(0x60, _ToReflectedField);
        impl.setPointer(0x68, _Throw);
        impl.setPointer(0x70, _ThrowNew);
        impl.setPointer(0x78, _ExceptionOccurred);
        impl.setPointer(0x80, _ExceptionDescribe);
        impl.setPointer(0x88, _ExceptionClear);
        impl.setPointer(0x90, _FatalError);
        impl.setPointer(0x98, _PushLocalFrame);
        impl.setPointer(0xa0, _PopLocalFrame);
        impl.setPointer(0xa8, _NewGlobalRef);
        impl.setPointer(0xb0, _DeleteGlobalRef);
        impl.setPointer(0xb8, _DeleteLocalRef);
        impl.setPointer(0xc0, _IsSameObject);
        impl.setPointer(0xc8, _NewLocalRef);
        impl.setPointer(0xd0, _EnsureLocalCapacity);
        impl.setPointer(0xd8, _AllocObject);
        impl.setPointer(0xe0, _NewObject);
        impl.setPointer(0xe8, _NewObjectV);
        impl.setPointer(0xf0, _NewObjectA);
        impl.setPointer(0xf8, _GetObjectClass);
        impl.setPointer(0x100, _IsInstanceOf);
        impl.setPointer(0x108, _GetMethodID);
        impl.setPointer(0x110, _CallObjectMethod);
        impl.setPointer(0x118, _CallObjectMethodV);
        impl.setPointer(0x120, _CallObjectMethodA);
        impl.setPointer(0x128, _CallBooleanMethod);
        impl.setPointer(0x130, _CallBooleanMethodV);
        impl.setPointer(0x138, _CallBooleanMethodA);
        impl.setPointer(0x140, _CallByteMethod);
        impl.setPointer(0x148, _CallByteMethodV);
        impl.setPointer(0x150, _CallByteMethodA);
        impl.setPointer(0x158, _CallCharMethod);
        impl.setPointer(0x160, _CallCharMethodV);
        impl.setPointer(0x168, _CallCharMethodA);
        impl.setPointer(0x170, _CallShortMethod);
        impl.setPointer(0x178, _CallShortMethodV);
        impl.setPointer(0x180, _CallShortMethodA);
        impl.setPointer(0x188, _CallIntMethod);
        impl.setPointer(0x190, _CallIntMethodV);
        impl.setPointer(0x198, _CallIntMethodA);
        impl.setPointer(0x1a0, _CallLongMethod);
        impl.setPointer(0x1a8, _CallLongMethodV);
        impl.setPointer(0x1b0, _CallLongMethodA);
        impl.setPointer(0x1b8, _CallFloatMethod);
        impl.setPointer(0x1c0, _CallFloatMethodV);
        impl.setPointer(0x1c8, _CallFloatMethodA);
        impl.setPointer(0x1d0, _CallDoubleMethod);
        impl.setPointer(0x1d8, _CallDoubleMethodV);
        impl.setPointer(0x1e0, _CallDoubleMethodA);
        impl.setPointer(0x1e8, _CallVoidMethod);
        impl.setPointer(0x1f0, _CallVoidMethodV);
        impl.setPointer(0x1f8, _CallVoidMethodA);
        impl.setPointer(0x200, _CallNonvirtualObjectMethod);
        impl.setPointer(0x208, _CallNonvirtualObjectMethodV);
        impl.setPointer(0x210, _CallNonvirtualObjectMethodA);
        impl.setPointer(0x218, _CallNonvirtualBooleanMethod);
        impl.setPointer(0x220, _CallNonvirtualBooleanMethodV);
        impl.setPointer(0x228, _CallNonvirtualBooleanMethodA);
        impl.setPointer(0x230, _CallNonvirtualByteMethod);
        impl.setPointer(0x238, _CallNonvirtualByteMethodV);
        impl.setPointer(0x240, _CallNonvirtualByteMethodA);
        impl.setPointer(0x248, _CallNonvirtualCharMethod);
        impl.setPointer(0x250, _CallNonvirtualCharMethodV);
        impl.setPointer(0x258, _CallNonvirtualCharMethodA);
        impl.setPointer(0x260, _CallNonvirtualShortMethod);
        impl.setPointer(0x268, _CallNonvirtualShortMethodV);
        impl.setPointer(0x270, _CallNonvirtualShortMethodA);
        impl.setPointer(0x278, _CallNonvirtualIntMethod);
        impl.setPointer(0x280, _CallNonvirtualIntMethodV);
        impl.setPointer(0x288, _CallNonvirtualIntMethodA);
        impl.setPointer(0x290, _CallNonvirtualLongMethod);
        impl.setPointer(0x298, _CallNonvirtualLongMethodV);
        impl.setPointer(0x2a0, _CallNonvirtualLongMethodA);
        impl.setPointer(0x2a8, _CallNonvirtualFloatMethod);
        impl.setPointer(0x2b0, _CallNonvirtualFloatMethodV);
        impl.setPointer(0x2b8, _CallNonvirtualFloatMethodA);
        impl.setPointer(0x2c0, _CallNonvirtualDoubleMethod);
        impl.setPointer(0x2c8, _CallNonvirtualDoubleMethodV);
        impl.setPointer(0x2d0, _CallNonvirtualDoubleMethodA);
        impl.setPointer(0x2d8, _CallNonvirtualVoidMethod);
        impl.setPointer(0x2e0, _CallNonvirtualVoidMethodV);
        impl.setPointer(0x2e8, _CallNonVirtualVoidMethodA);
        impl.setPointer(0x2f0, _GetFieldID);
        impl.setPointer(0x2f8, _GetObjectField);
        impl.setPointer(0x300, _GetBooleanField);
        impl.setPointer(0x308, _GetByteField);
        impl.setPointer(0x310, _GetCharField);
        impl.setPointer(0x318, _GetShortField);
        impl.setPointer(0x320, _GetIntField);
        impl.setPointer(0x328, _GetLongField);
        impl.setPointer(0x330, _GetFloatField);
        impl.setPointer(0x338, _GetDoubleField);
        impl.setPointer(0x340, _SetObjectField);
        impl.setPointer(0x348, _SetBooleanField);
        impl.setPointer(0x350, _SetByteField);
        impl.setPointer(0x358, _SetCharField);
        impl.setPointer(0x360, _SetShortField);
        impl.setPointer(0x368, _SetIntField);
        impl.setPointer(0x370, _SetLongField);
        impl.setPointer(0x378, _SetFloatField);
        impl.setPointer(0x380, _SetDoubleField);
        impl.setPointer(0x388, _GetStaticMethodID);
        impl.setPointer(0x390, _CallStaticObjectMethod);
        impl.setPointer(0x398, _CallStaticObjectMethodV);
        impl.setPointer(0x3a0, _CallStaticObjectMethodA);
        impl.setPointer(0x3a8, _CallStaticBooleanMethod);
        impl.setPointer(0x3b0, _CallStaticBooleanMethodV);
        impl.setPointer(0x3b8, _CallStaticBooleanMethodA);
        impl.setPointer(0x3c0, _CallStaticByteMethod);
        impl.setPointer(0x3c8, _CallStaticByteMethodV);
        impl.setPointer(0x3d0, _CallStaticByteMethodA);
        impl.setPointer(0x3d8, _CallStaticCharMethod);
        impl.setPointer(0x3e0, _CallStaticCharMethodV);
        impl.setPointer(0x3e8, _CallStaticCharMethodA);
        impl.setPointer(0x3f0, _CallStaticShortMethod);
        impl.setPointer(0x3f8, _CallStaticShortMethodV);
        impl.setPointer(0x400, _CallStaticShortMethodA);
        impl.setPointer(0x408, _CallStaticIntMethod);
        impl.setPointer(0x410, _CallStaticIntMethodV);
        impl.setPointer(0x418, _CallStaticIntMethodA);
        impl.setPointer(0x420, _CallStaticLongMethod);
        impl.setPointer(0x428, _CallStaticLongMethodV);
        impl.setPointer(0x430, _CallStaticLongMethodA);
        impl.setPointer(0x438, _CallStaticFloatMethod);
        impl.setPointer(0x440, _CallStaticFloatMethodV);
        impl.setPointer(0x448, _CallStaticFloatMethodA);
        impl.setPointer(0x450, _CallStaticDoubleMethod);
        impl.setPointer(0x458, _CallStaticDoubleMethodV);
        impl.setPointer(0x460, _CallStaticDoubleMethodA);
        impl.setPointer(0x468, _CallStaticVoidMethod);
        impl.setPointer(0x470, _CallStaticVoidMethodV);
        impl.setPointer(0x478, _CallStaticVoidMethodA);
        impl.setPointer(0x480, _GetStaticFieldID);
        impl.setPointer(0x488, _GetStaticObjectField);
        impl.setPointer(0x490, _GetStaticBooleanField);
        impl.setPointer(0x498, _GetStaticByteField);
        impl.setPointer(0x4a0, _GetStaticCharField);
        impl.setPointer(0x4a8, _GetStaticShortField);
        impl.setPointer(0x4b0, _GetStaticIntField);
        impl.setPointer(0x4b8, _GetStaticLongField);
        impl.setPointer(0x4c0, _GetStaticFloatField);
        impl.setPointer(0x4c8, _GetStaticDoubleField);
        impl.setPointer(0x4d0, _SetStaticObjectField);
        impl.setPointer(0x4d8, _SetStaticBooleanField);
        impl.setPointer(0x4e0, _SetStaticByteField);
        impl.setPointer(0x4e8, _SetStaticCharField);
        impl.setPointer(0x4f0, _SetStaticShortField);
        impl.setPointer(0x4f8, _SetStaticIntField);
        impl.setPointer(0x500, _SetStaticLongField);
        impl.setPointer(0x508, _SetStaticFloatField);
        impl.setPointer(0x510, _SetStaticDoubleField);
        impl.setPointer(0x518, _NewString);
        impl.setPointer(0x520, _GetStringLength);
        impl.setPointer(0x528, _GetStringChars);
        impl.setPointer(0x530, _ReleaseStringChars);
        impl.setPointer(0x538, _NewStringUTF);
        impl.setPointer(0x540, _GetStringUTFLength);
        impl.setPointer(0x548, _GetStringUTFChars);
        impl.setPointer(0x550, _ReleaseStringUTFChars);
        impl.setPointer(0x558, _GetArrayLength);
        impl.setPointer(0x560, _NewObjectArray);
        impl.setPointer(0x568, _GetObjectArrayElement);
        impl.setPointer(0x570, _SetObjectArrayElement);
        impl.setPointer(0x578, _NewBooleanArray);
        impl.setPointer(0x580, _NewByteArray);
        impl.setPointer(0x588, _NewCharArray);
        impl.setPointer(0x590, _NewShortArray);
        impl.setPointer(0x598, _NewIntArray);
        impl.setPointer(0x5a0, _NewLongArray);
        impl.setPointer(0x5a8, _NewFloatArray);
        impl.setPointer(0x5b0, _NewDoubleArray);
        impl.setPointer(0x5b8, _GetBooleanArrayElements);
        impl.setPointer(0x5c0, _GetByteArrayElements);
        impl.setPointer(0x5c8, _GetCharArrayElements);
        impl.setPointer(0x5d0, _GetShortArrayElements);
        impl.setPointer(0x5d8, _GetIntArrayElements);
        impl.setPointer(0x5e0, _GetLongArrayElements);
        impl.setPointer(0x5e8, _GetFloatArrayElements);
        impl.setPointer(0x5f0, _GetDoubleArrayElements);
        impl.setPointer(0x5f8, _ReleaseBooleanArrayElements);
        impl.setPointer(0x600, _ReleaseByteArrayElements);
        impl.setPointer(0x608, _ReleaseCharArrayElements);
        impl.setPointer(0x610, _ReleaseShortArrayElements);
        impl.setPointer(0x618, _ReleaseIntArrayElements);
        impl.setPointer(0x620, _ReleaseLongArrayElements);
        impl.setPointer(0x628, _ReleaseFloatArrayElements);
        impl.setPointer(0x630, _ReleaseDoubleArrayElements);
        impl.setPointer(0x638, _GetBooleanArrayRegion);
        impl.setPointer(0x640, _GetByteArrayRegion);
        impl.setPointer(0x648, _GetCharArrayRegion);
        impl.setPointer(0x650, _GetShortArrayRegion);
        impl.setPointer(0x658, _GetIntArrayRegion);
        impl.setPointer(0x660, _GetLongArrayRegion);
        impl.setPointer(0x668, _GetFloatArrayRegion);
        impl.setPointer(0x670, _GetDoubleArrayRegion);
        impl.setPointer(0x678, _SetBooleanArrayRegion);
        impl.setPointer(0x680, _SetByteArrayRegion);
        impl.setPointer(0x688, _SetCharArrayRegion);
        impl.setPointer(0x690, _SetShortArrayRegion);
        impl.setPointer(0x698, _SetIntArrayRegion);
        impl.setPointer(0x6a0, _SetLongArrayRegion);
        impl.setPointer(0x6a8, _SetFloatArrayRegion);
        impl.setPointer(0x6b0, _SetDoubleArrayRegion);
        impl.setPointer(0x6b8, _RegisterNatives);
        impl.setPointer(0x6c0, _UnregisterNatives);
        impl.setPointer(0x6c8, _MonitorEnter);
        impl.setPointer(0x6d0, _MonitorExit);
        impl.setPointer(0x6d8, _GetJavaVM);
        impl.setPointer(0x6e0, _GetStringRegion);
        impl.setPointer(0x6e8, _GetStringUTFRegion);
        impl.setPointer(0x6f0, _GetPrimitiveArrayCritical);
        impl.setPointer(0x6f8, _ReleasePrimitiveArrayCritical);
        impl.setPointer(0x700, _GetStringCritical);
        impl.setPointer(0x708, _ReleaseStringCritical);
        impl.setPointer(0x710, _NewWeakGlobalRef);
        impl.setPointer(0x718, _DeleteWeakGlobalRef);
        impl.setPointer(0x720, _ExceptionCheck);
        impl.setPointer(0x728, _NewDirectByteBuffer);
        impl.setPointer(0x730, _GetDirectBufferAddress);
        impl.setPointer(0x738, _GetDirectBufferCapacity);
        impl.setPointer(0x740, _GetObjectRefType);
        impl.setPointer(last, _GetModule);

        _JNIEnv = svcMemory.allocate(emulator.getPointerSize(), "_JNIEnv");
        _JNIEnv.setPointer(0, impl);

        UnidbgPointer _AttachCurrentThread = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                Pointer vm = context.getPointerArg(0);
                Pointer env = context.getPointerArg(1);
                Pointer args = context.getPointerArg(2); // JavaVMAttachArgs*
                if (log.isDebugEnabled()) {
                    log.debug("AttachCurrentThread vm=" + vm + ", env=" + env.getPointer(0) + ", args=" + args);
                }
                env.setPointer(0, _JNIEnv);
                return JNI_OK;
            }
        });

        UnidbgPointer _GetEnv = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext context = emulator.getContext();
                Pointer vm = context.getPointerArg(0);
                Pointer env = context.getPointerArg(1);
                int version = context.getIntArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("GetEnv vm=" + vm + ", env=" + env.getPointer(0) + ", version=0x" + Integer.toHexString(version));
                }
                env.setPointer(0, _JNIEnv);
                return JNI_OK;
            }
        });

        UnidbgPointer _JNIInvokeInterface = svcMemory.allocate(emulator.getPointerSize() * 8, "_JNIInvokeInterface");
        for (int i = 0; i < emulator.getPointerSize() * 8; i += emulator.getPointerSize()) {
            _JNIInvokeInterface.setInt(i, i);
        }
        _JNIInvokeInterface.setPointer(emulator.getPointerSize() * 4L, _AttachCurrentThread);
        _JNIInvokeInterface.setPointer(emulator.getPointerSize() * 6L, _GetEnv);

        _JavaVM.setPointer(0, _JNIInvokeInterface);

        if (log.isDebugEnabled()) {
            log.debug("_JavaVM=" + _JavaVM + ", _JNIInvokeInterface=" + _JNIInvokeInterface + ", _JNIEnv=" + _JNIEnv);
        }
    }

    @Override
    public Pointer getJavaVM() {
        return _JavaVM;
    }

    @Override
    public Pointer getJNIEnv() {
        return _JNIEnv;
    }

    byte[] loadLibraryData(Apk apk, String soName) {
        byte[] soData = apk.getFileData("lib/arm64-v8a/" + soName);
        if (soData != null) {
            if (log.isDebugEnabled()) {
                log.debug("resolve arm64-v8a library: " + soName);
            }
            return soData;
        } else {
            return null;
        }
    }
}
