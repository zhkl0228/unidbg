package cn.banny.unidbg.linux.android.dvm;

import cn.banny.auxiliary.Inspector;
import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.arm.ArmSvc;
import cn.banny.unidbg.arm.context.Arm32RegisterContext;
import cn.banny.unidbg.arm.context.EditableArm32RegisterContext;
import cn.banny.unidbg.linux.android.dvm.array.*;
import cn.banny.unidbg.memory.MemoryBlock;
import cn.banny.unidbg.memory.SvcMemory;
import cn.banny.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;
import net.dongliu.apk.parser.ApkFile;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.ArmConst;
import unicorn.Unicorn;
import unicorn.UnicornException;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class DalvikVM extends BaseVM implements VM {

    private static final Log log = LogFactory.getLog(DalvikVM.class);

    private final UnicornPointer _JavaVM;
    private final UnicornPointer _JNIEnv;

    public DalvikVM(Emulator emulator, File apkFile) {
        super(emulator, apkFile);

        final SvcMemory svcMemory = emulator.getSvcMemory();
        _JavaVM = svcMemory.allocate(emulator.getPointerSize(), "_JavaVM");

        Pointer _FindClass = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                Arm32RegisterContext context = emulator.getContext();
                Pointer env = context.getR0Pointer();
                Pointer className = context.getR1Pointer();
                String name = className.getString(0);

                if (notFoundClassSet.contains(name)) {
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

        Pointer _ToReflectedMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                Arm32RegisterContext context = emulator.getContext();
                UnicornPointer clazz = context.getR1Pointer();
                UnicornPointer jmethodID = context.getR2Pointer();
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                DvmMethod dvmMethod = null;
                if (dvmClass != null) {
                    dvmMethod = dvmClass.getStaticMethod(jmethodID.toUIntPeer());
                    if (dvmMethod == null) {
                        dvmMethod = dvmClass.getMethod(jmethodID.toUIntPeer());
                    }
                }
                if (log.isDebugEnabled()) {
                    log.debug("ToReflectedMethod clazz=" + dvmClass + ", jmethodID=" + jmethodID + ", lr=" + context.getLRPointer());
                }
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->ToReflectedMethod(%s, %s, %s) was called", dvmClass.value, dvmMethod.methodName, dvmMethod.isStatic));
                    }

                    return addLocalObject(dvmMethod.toReflectedMethod());
                }
            }
        }) ;

        Pointer _Throw = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                DvmObject<?> dvmObject = getObject(object.toUIntPeer());
                log.warn("Throw object=" + object + ", dvmObject=" + dvmObject + ", class=" + dvmObject.getObjectType());
                throwable = dvmObject;
                return 0;
            }
        });

        Pointer _ExceptionOccurred = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                if (log.isDebugEnabled()) {
                    log.debug("ExceptionOccurred");
                }
                return throwable == null ? JNI_NULL : (throwable.hashCode() & 0xffffffffL);
            }
        });

        Pointer _ExceptionClear = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                if (log.isDebugEnabled()) {
                    log.debug("ExceptionClear");
                }
                throwable = null;
                return 0;
            }
        });

        Pointer _PushLocalFrame = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                int capacity = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("PushLocalFrame capacity=" + capacity);
                }
                return JNI_OK;
            }
        });

        Pointer _PopLocalFrame = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer jresult = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                if (log.isDebugEnabled()) {
                    log.debug("PopLocalFrame jresult=" + jresult);
                }
                return jresult == null ? 0 : jresult.toUIntPeer();
            }
        });

        Pointer _NewGlobalRef = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                if (object == null) {
                    return 0;
                }
                DvmObject<?> dvmObject = getObject(object.toUIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("NewGlobalRef object=" + object + ", dvmObject=" + dvmObject + ", class=" + dvmObject.getClass());
                }
                addObject(dvmObject, true);
                return object.toUIntPeer();
            }
        });

        Pointer _DeleteGlobalRef = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                if (log.isDebugEnabled()) {
                    log.debug("DeleteGlobalRef object=" + object);
                }
                globalObjectMap.remove(object.toUIntPeer());
                return 0;
            }
        });

        Pointer _DeleteLocalRef = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                if (log.isDebugEnabled()) {
                    log.debug("DeleteLocalRef object=" + object);
                }
                localObjectMap.remove(object.toUIntPeer());
                return 0;
            }
        });

        Pointer _IsSameObject = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer ref1 = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer ref2 = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (log.isDebugEnabled()) {
                    log.debug("IsSameObject ref1=" + ref1 + ", ref2=" + ref2);
                }
                if (verbose) {
                    System.out.println(String.format("JNIEnv->IsSameObject(0x%x, 0x%x) was called", ref1.toUIntPeer(), ref2.toUIntPeer()));
                }
                return ref1 == ref2 || ref1.equals(ref2) ? JNI_TRUE : JNI_FALSE;
            }
        });

        Pointer _NewLocalRef = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                DvmObject<?> dvmObject = getObject(object.toUIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("NewLocalRef object=" + object + ", dvmObject=" + dvmObject + ", class=" + dvmObject.getClass());
                }
                if (verbose) {
                    System.out.println(String.format("JNIEnv->NewLocalRef(0x%x) was called", object.toUIntPeer()));
                }
                return object.toUIntPeer();
            }
        });

        Pointer _EnsureLocalCapacity = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                int capacity = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("EnsureLocalCapacity capacity=" + capacity);
                }
                return 0;
            }
        });

        Pointer _NewObject = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toUIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("NewObjectV clazz=" + dvmClass + ", jmethodID=" + jmethodID + ", lr=" + UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                }
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->NewObject(%s, %s) was called", dvmClass.value, dvmMethod.methodName));
                    }
                    return dvmMethod.newObject(ArmVarArg.create(emulator, DalvikVM.this));
                }
            }
        });

        Pointer _NewObjectV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                UnicornPointer va_list = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toUIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("NewObjectV clazz=" + dvmClass + ", jmethodID=" + jmethodID + ", va_list=" + va_list + ", lr=" + UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                }
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->NewObjectV(%s, %s, 0x%x) was called", dvmClass.value, dvmMethod.methodName, va_list.toUIntPeer()));
                    }
                    return dvmMethod.newObjectV(new VaList32(DalvikVM.this, va_list));
                }
            }
        });

        Pointer _GetObjectClass = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                DvmObject<?> dvmObject = getObject(object.toUIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("GetObjectClass object=" + object + ", dvmObject=" + dvmObject);
                }
                if (dvmObject == null) {
                    throw new UnicornException();
                } else {
                    DvmClass dvmClass = dvmObject.objectType;
                    return dvmClass.hashCode();
                }
            }
        });

        Pointer _IsInstanceOf = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                DvmObject<?> dvmObject = getObject(object.toUIntPeer());
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("IsInstanceOf object=" + object + ", clazz=" + clazz + ", dvmObject=" + dvmObject + ", dvmClass=" + dvmClass);
                }
                if (dvmObject == null || dvmClass == null) {
                    throw new UnicornException();
                }
                return dvmObject.isInstanceOf(DalvikVM.this, dvmClass) ? JNI_TRUE : JNI_FALSE;
            }
        });

        Pointer _GetMethodID = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                Pointer methodName = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                Pointer argsPointer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
                String name = methodName.getString(0);
                String args = argsPointer.getString(0);
                if (log.isDebugEnabled()) {
                    log.debug("GetMethodID class=" + clazz + ", methodName=" + name + ", args=" + args);
                }
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                if (dvmClass == null) {
                    throw new UnicornException();
                } else {
                    return dvmClass.getMethodID(name, args);
                }
            }
        });

        Pointer _CallObjectMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (log.isDebugEnabled()) {
                    log.debug("CallObjectMethod object=" + object + ", jmethodID=" + jmethodID);
                }
                DvmObject<?> dvmObject = getObject(object.toUIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toUIntPeer());
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->CallObjectMethod(%s, %s%s) was called", dvmClass.value, dvmMethod.methodName, dvmMethod.args));
                    }
                    return addObject(dvmMethod.callObjectMethod(dvmObject, ArmVarArg.create(emulator, DalvikVM.this)), false);
                }
            }
        });

        Pointer _CallObjectMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                UnicornPointer va_list = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
                if (log.isDebugEnabled()) {
                    log.debug("CallObjectMethodV object=" + object + ", jmethodID=" + jmethodID + ", va_list=" + va_list + ", lr=" + UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                }
                DvmObject<?> dvmObject = getObject(object.toUIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toUIntPeer());
                if (dvmMethod == null) {
                    throw new UnicornException("dvmObject=" + dvmObject + ", dvmClass=" + dvmClass + ", jmethodID=" + jmethodID);
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->CallObjectMethodV(%s, %s%s, 0x%x) was called", dvmClass.value, dvmMethod.methodName, dvmMethod.args, va_list.toUIntPeer()));
                    }
                    return addObject(dvmMethod.callObjectMethodV(dvmObject, new VaList32(DalvikVM.this, va_list)), false);
                }
            }
        });

        Pointer _CallBooleanMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (log.isDebugEnabled()) {
                    log.debug("CallBooleanMethod object=" + object + ", jmethodID=" + jmethodID);
                }
                DvmObject<?> dvmObject = getObject(object.toUIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toUIntPeer());
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->CallBooleanMethod(%s, %s%s) was called", dvmClass.value, dvmMethod.methodName, dvmMethod.args));
                    }
                    return dvmMethod.callBooleanMethod(dvmObject, ArmVarArg.create(emulator, DalvikVM.this));
                }
            }
        });

        Pointer _CallBooleanMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                UnicornPointer va_list = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
                if (log.isDebugEnabled()) {
                    log.debug("CallBooleanMethodV object=" + object + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmObject<?> dvmObject = getObject(object.toUIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toUIntPeer());
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->CallBooleanMethodV(%s, %s%s, 0x%x) was called", dvmClass.value, dvmMethod.methodName, dvmMethod.args, va_list.toUIntPeer()));
                    }
                    return dvmMethod.callBooleanMethodV(dvmObject, new VaList32(DalvikVM.this, va_list));
                }
            }
        });

        Pointer _CallIntMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (log.isDebugEnabled()) {
                    log.debug("CallIntMethod object=" + object + ", jmethodID=" + jmethodID);
                }
                DvmObject<?> dvmObject = getObject(object.toUIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toUIntPeer());
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->CallIntMethod(%s, %s%s) was called", dvmClass.value, dvmMethod.methodName, dvmMethod.args));
                    }
                    return dvmMethod.callIntMethod(dvmObject, ArmVarArg.create(emulator, DalvikVM.this));
                }
            }
        });

        Pointer _CallIntMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                UnicornPointer va_list = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
                if (log.isDebugEnabled()) {
                    log.debug("CallIntMethodV object=" + object + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmObject<?> dvmObject = getObject(object.toUIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toUIntPeer());
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->CallIntMethodV(%s, %s%s, 0x%x) was called", dvmClass.value, dvmMethod.methodName, dvmMethod.args, va_list.toUIntPeer()));
                    }
                    return dvmMethod.callIntMethodV(dvmObject, new VaList32(DalvikVM.this, va_list));
                }
            }
        });

        Pointer _CallLongMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                UnicornPointer va_list = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
                if (log.isDebugEnabled()) {
                    log.debug("CallLongMethodV object=" + object + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmObject<?> dvmObject = getObject(object.toUIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toUIntPeer());
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->CallLongMethodV(%s, %s%s, 0x%x) was called", dvmClass.value, dvmMethod.methodName, dvmMethod.args, va_list.toUIntPeer()));
                    }
                    long value = dvmMethod.callLongMethodV(dvmObject, new VaList32(DalvikVM.this, va_list));
                    emulator.getUnicorn().reg_write(ArmConst.UC_ARM_REG_R1, (int) (value >> 32));
                    return (value & 0xffffffffL);
                }
            }
        });

        Pointer _CallFloatMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                UnicornPointer va_list = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
                if (log.isDebugEnabled()) {
                    log.debug("CallFloatMethodV object=" + object + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmObject<?> dvmObject = getObject(object.toUIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toUIntPeer());
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->CallFloatMethodV(%s, %s%s, 0x%x) was called", dvmClass.value, dvmMethod.methodName, dvmMethod.args, va_list.toUIntPeer()));
                    }
                    float value = dvmMethod.callFloatMethodV(dvmObject, new VaList32(DalvikVM.this, va_list));
                    ByteBuffer buffer = ByteBuffer.allocate(4);
                    buffer.order(ByteOrder.LITTLE_ENDIAN);
                    buffer.putFloat(value);
                    buffer.flip();
                    return (buffer.getInt() & 0xffffffffL);
                }
            }
        });

        Pointer _CallVoidMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (log.isDebugEnabled()) {
                    log.debug("CallVoidMethod object=" + object + ", jmethodID=" + jmethodID);
                }
                DvmObject<?> dvmObject = getObject(object.toUIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toUIntPeer());
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->CallVoidMethod(%s, %s%s) was called", dvmClass.value, dvmMethod.methodName, dvmMethod.args));
                    }
                    dvmMethod.callVoidMethod(dvmObject, ArmVarArg.create(emulator, DalvikVM.this));
                    return 0;
                }
            }
        });

        Pointer _CallVoidMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                UnicornPointer va_list = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
                if (log.isDebugEnabled()) {
                    log.debug("CallVoidMethodV object=" + object + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmObject<?> dvmObject = getObject(object.toUIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getMethod(jmethodID.toUIntPeer());
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->CallVoidMethodV(%s, %s%s, 0x%x) was called", dvmClass.value, dvmMethod.methodName, dvmMethod.args, va_list.toUIntPeer()));
                    }
                    dvmMethod.callVoidMethodV(dvmObject, new VaList32(DalvikVM.this, va_list));
                    return 0;
                }
            }
        });

        Pointer _GetFieldID = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                Pointer fieldName = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                Pointer argsPointer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
                String name = fieldName.getString(0);
                String args = argsPointer.getString(0);
                if (log.isDebugEnabled()) {
                    log.debug("GetFieldID class=" + clazz + ", fieldName=" + name + ", args=" + args);
                }
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                if (dvmClass == null) {
                    throw new UnicornException();
                } else {
                    return dvmClass.getFieldID(name, args);
                }
            }
        });

        Pointer _GetObjectField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jfieldID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (log.isDebugEnabled()) {
                    log.debug("GetObjectField object=" + object + ", jfieldID=" + jfieldID);
                }
                DvmObject<?> dvmObject = getObject(object.toUIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toUIntPeer());
                if (dvmField == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->GetObjectField(%s, %s%s) was called", dvmClass.value, dvmField.fieldName, dvmField.fieldType));
                    }
                    return dvmField.getObjectField(dvmObject);
                }
            }
        });

        Pointer _GetBooleanField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jfieldID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (log.isDebugEnabled()) {
                    log.debug("GetBooleanField object=" + object + ", jfieldID=" + jfieldID);
                }
                DvmObject<?> dvmObject = getObject(object.toUIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toUIntPeer());
                if (dvmField == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->GetBooleanField(%s, %s%s) was called", dvmClass.value, dvmField.fieldName, dvmField.fieldType));
                    }
                    return dvmField.getBooleanField(dvmObject);
                }
            }
        });

        Pointer _GetIntField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jfieldID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (log.isDebugEnabled()) {
                    log.debug("GetIntField object=" + object + ", jfieldID=" + jfieldID);
                }
                DvmObject<?> dvmObject = getObject(object.toUIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toUIntPeer());
                if (dvmField == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->GetIntField(%s, %s%s) was called", dvmClass.value, dvmField.fieldName, dvmField.fieldType));
                    }
                    return dvmField.getIntField(dvmObject);
                }
            }
        });

        Pointer _GetLongField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                EditableArm32RegisterContext context = emulator.getContext();
                UnicornPointer object = context.getPointerArg(1);
                UnicornPointer jfieldID = context.getPointerArg(2);
                if (log.isDebugEnabled()) {
                    log.debug("GetLongField object=" + object + ", jfieldID=" + jfieldID);
                }
                DvmObject<?> dvmObject = getObject(object.toUIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toUIntPeer());
                if (dvmField == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->GetLongField(%s, %s%s) was called", dvmClass.value, dvmField.fieldName, dvmField.fieldType));
                    }
                    long value = dvmField.getLongField(dvmObject);
                    context.setR1((int) (value >> 32));
                    return value;
                }
            }
        });

        Pointer _SetObjectField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jfieldID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                UnicornPointer value = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
                if (log.isDebugEnabled()) {
                    log.debug("SetObjectField object=" + object + ", jfieldID=" + jfieldID + ", value=" + value);
                }
                DvmObject<?> dvmObject = getObject(object.toUIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toUIntPeer());
                if (dvmField == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->SetObjectField(%s, %s%s, 0x%x) was called", dvmClass.value, dvmField.fieldName, dvmField.fieldType, value.toUIntPeer()));
                    }
                    dvmField.setObjectField(dvmObject, getObject(value.toUIntPeer()));
                }
                return 0;
            }
        });

        Pointer _SetBooleanField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jfieldID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                int value = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("SetBooleanField object=" + object + ", jfieldID=" + jfieldID + ", value=" + value);
                }
                DvmObject<?> dvmObject = getObject(object.toUIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toUIntPeer());
                if (dvmField == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->SetBooleanField(%s, %s%s, %s) was called", dvmClass.value, dvmField.fieldName, dvmField.fieldType, value == JNI_TRUE));
                    }
                    dvmField.setBooleanField(dvmObject, value == JNI_TRUE);
                }
                return 0;
            }
        });

        Pointer _SetIntField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jfieldID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                int value = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("SetIntField object=" + object + ", jfieldID=" + jfieldID + ", value=" + value);
                }
                DvmObject<?> dvmObject = getObject(object.toUIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toUIntPeer());
                if (dvmField == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->SetIntField(%s, %s%s, %d) was called", dvmClass.value, dvmField.fieldName, dvmField.fieldType, value));
                    }
                    dvmField.setIntField(dvmObject, value);
                }
                return 0;
            }
        });
        
        Pointer _SetLongField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jfieldID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                UnicornPointer sp = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_SP);
                long value = sp.getLong(0);
                if (log.isDebugEnabled()) {
                    log.debug("SetLongField object=" + object + ", jfieldID=" + jfieldID + ", value=" + value);
                }
                DvmObject<?> dvmObject = getObject(object.toUIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toUIntPeer());
                if (dvmField == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->SetLongField(%s, %s%s, %d) was called", dvmClass.value, dvmField.fieldName, dvmField.fieldType, value));
                    }
                    dvmField.setLongField(dvmObject, value);
                }
                return 0;
            }
        });
        
        Pointer _SetDoubleField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jfieldID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                UnicornPointer sp = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_SP);
                double value = sp.getDouble(0);
                if (log.isDebugEnabled()) {
                    log.debug("SetDoubleField object=" + object + ", jfieldID=" + jfieldID + ", value=" + value);
                }
                DvmObject<?> dvmObject = getObject(object.toUIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmField dvmField = dvmClass == null ? null : dvmClass.getField(jfieldID.toUIntPeer());
                if (dvmField == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->SetDoubleField(%s, %s%s, %f) was called", dvmClass.value, dvmField.fieldName, dvmField.fieldType, value));
                    }
                    dvmField.setDoubleField(dvmObject, value);
                }
                return 0;
            }
        });

        Pointer _GetStaticMethodID = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                Pointer methodName = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                Pointer argsPointer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
                String name = methodName.getString(0);
                String args = argsPointer.getString(0);
                if (log.isDebugEnabled()) {
                    log.debug("GetStaticMethodID class=" + clazz + ", methodName=" + name + ", args=" + args);
                }
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                if (dvmClass == null) {
                    throw new UnicornException();
                } else {
                    return dvmClass.getStaticMethodID(name, args);
                }
            }
        });

        Pointer _CallStaticObjectMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticObjectMethod clazz=" + clazz + ", jmethodID=" + jmethodID);
                }
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toUIntPeer());
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->CallStaticObjectMethod(%s, %s%s) was called", dvmClass.value, dvmMethod.methodName, dvmMethod.args));
                    }
                    return addObject(dvmMethod.callStaticObjectMethod(ArmVarArg.create(emulator, DalvikVM.this)), false);
                }
            }
        });

        Pointer _CallStaticObjectMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                UnicornPointer va_list = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticObjectMethodV clazz=" + clazz + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toUIntPeer());
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->CallStaticObjectMethodV(%s, %s%s, 0x%x) was called", dvmClass.value, dvmMethod.methodName, dvmMethod.args, va_list.toUIntPeer()));
                    }
                    return addObject(dvmMethod.callStaticObjectMethodV(new VaList32(DalvikVM.this, va_list)), false);
                }
            }
        });

        Pointer _CallStaticBooleanMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticBooleanMethod clazz=" + clazz + ", jmethodID=" + jmethodID);
                }
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toUIntPeer());
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->CallStaticBooleanMethod(%s, %s%s) was called", dvmClass.value, dvmMethod.methodName, dvmMethod.args));
                    }
                    return dvmMethod.CallStaticBooleanMethod(ArmVarArg.create(emulator, DalvikVM.this));
                }
            }
        });

        Pointer _CallStaticBooleanMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                UnicornPointer va_list = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticBooleanMethodV clazz=" + clazz + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toUIntPeer());
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->CallStaticBooleanMethodV(%s, %s%s, 0x%x) was called", dvmClass.value, dvmMethod.methodName, dvmMethod.args, va_list.toUIntPeer()));
                    }
                    return dvmMethod.callStaticBooleanMethodV(new VaList32(DalvikVM.this, va_list));
                }
            }
        });

        Pointer _CallStaticIntMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticIntMethodV clazz=" + clazz + ", jmethodID=" + jmethodID);
                }
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toUIntPeer());
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->CallStaticIntMethod(%s, %s%s) was called", dvmClass.value, dvmMethod.methodName, dvmMethod.args));
                    }
                    return dvmMethod.callStaticIntMethod(ArmVarArg.create(emulator, DalvikVM.this));
                }
            }
        });

        Pointer _CallStaticIntMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                UnicornPointer va_list = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticIntMethodV clazz=" + clazz + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toUIntPeer());
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->CallStaticIntMethodV(%s, %s%s, 0x%x) was called", dvmClass.value, dvmMethod.methodName, dvmMethod.args, va_list.toUIntPeer()));
                    }
                    return dvmMethod.callStaticIntMethodV(new VaList32(DalvikVM.this, va_list));
                }
            }
        });

        Pointer _CallStaticLongMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticLongMethod clazz=" + clazz + ", jmethodID=" + jmethodID);
                }
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toUIntPeer());
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->CallStaticLongMethod(%s, %s%s) was called", dvmClass.value, dvmMethod.methodName, dvmMethod.args));
                    }
                    long value = dvmMethod.callStaticLongMethod(ArmVarArg.create(emulator, DalvikVM.this));
                    emulator.getUnicorn().reg_write(ArmConst.UC_ARM_REG_R1, (int) (value >> 32));
                    return (value & 0xffffffffL);
                }
            }
        });

        Pointer _CallStaticLongMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                UnicornPointer va_list = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticLongMethodV clazz=" + clazz + ", jmethodID=" + jmethodID + ", va_list=" + va_list + ", lr=" + UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                }
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toUIntPeer());
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->CallStaticLongMethodV(%s, %s%s, 0x%x) was called", dvmClass.value, dvmMethod.methodName, dvmMethod.args, va_list.toUIntPeer()));
                    }
                    long value = dvmMethod.callStaticLongMethodV(new VaList32(DalvikVM.this, va_list));
                    emulator.getUnicorn().reg_write(ArmConst.UC_ARM_REG_R1, (int) (value >> 32));
                    return (value & 0xffffffffL);
                }
            }
        });

        Pointer _CallStaticVoidMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticVoidMethod clazz=" + clazz + ", jmethodID=" + jmethodID);
                }
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toUIntPeer());
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->CallStaticVoidMethod(%s, %s%s) was called", dvmClass.value, dvmMethod.methodName, dvmMethod.args));
                    }
                    dvmMethod.callStaticVoidMethod(ArmVarArg.create(emulator, DalvikVM.this));
                    return 0;
                }
            }
        });

        Pointer _CallStaticVoidMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                UnicornPointer va_list = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticVoidMethodV clazz=" + clazz + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.getStaticMethod(jmethodID.toUIntPeer());
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->CallStaticVoidMethodV(%s, %s%s, 0x%x) was called", dvmClass.value, dvmMethod.methodName, dvmMethod.args, va_list.toUIntPeer()));
                    }
                    dvmMethod.callStaticVoidMethodV(new VaList32(DalvikVM.this, va_list));
                    return 0;
                }
            }
        });

        Pointer _GetStaticFieldID = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                Pointer fieldName = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                Pointer argsPointer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
                String name = fieldName.getString(0);
                String args = argsPointer.getString(0);
                if (log.isDebugEnabled()) {
                    log.debug("GetStaticFieldID class=" + clazz + ", fieldName=" + name + ", args=" + args);
                }
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                if (dvmClass == null) {
                    throw new UnicornException();
                } else {
                    return dvmClass.getStaticFieldID(name, args);
                }
            }
        });

        Pointer _GetStaticObjectField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jfieldID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (log.isDebugEnabled()) {
                    log.debug("GetStaticObjectField clazz=" + clazz + ", jfieldID=" + jfieldID);
                }
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                DvmField dvmField = dvmClass == null ? null : dvmClass.getStaticField(jfieldID.toUIntPeer());
                if (dvmField == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->GetStaticObjectField(%s, %s, %s) was called", dvmClass.value, dvmField.fieldName, dvmField.fieldType));
                    }
                    return dvmField.getStaticObjectField();
                }
            }
        });

        Pointer _GetStaticIntField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jfieldID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (log.isDebugEnabled()) {
                    log.debug("GetStaticIntField clazz=" + clazz + ", jfieldID=" + jfieldID);
                }
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                DvmField dvmField = dvmClass == null ? null : dvmClass.getStaticField(jfieldID.toUIntPeer());
                if (dvmField == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->GetStaticIntField(%s, %s) was called", dvmClass.value, dvmField.fieldName));
                    }
                    return dvmField.getStaticIntField();
                }
            }
        });

        Pointer _GetStaticLongField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                EditableArm32RegisterContext context = emulator.getContext();
                UnicornPointer clazz = context.getR1Pointer();
                UnicornPointer jfieldID = context.getR2Pointer();
                if (log.isDebugEnabled()) {
                    log.debug("GetStaticLongField clazz=" + clazz + ", jfieldID=" + jfieldID);
                }
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                DvmField dvmField = dvmClass == null ? null : dvmClass.getStaticField(jfieldID.toUIntPeer());
                if (dvmField == null) {
                    throw new UnicornException();
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->GetStaticLongField(%s, %s) was called", dvmClass.value, dvmField.fieldName));
                    }
                    long value = dvmField.getStaticLongField();
                    context.setR1((int) (value >> 32));
                    return value;
                }
            }
        });

        Pointer _SetStaticLongField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jfieldID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                UnicornPointer sp = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_SP);
                long value = sp.getLong(0);
                if (log.isDebugEnabled()) {
                    log.debug("SetStaticLongField clazz=" + clazz + ", jfieldID=" + jfieldID + ", value=" + value);
                }
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                DvmField dvmField = dvmClass == null ? null : dvmClass.getStaticField(jfieldID.toUIntPeer());
                if (dvmField == null) {
                    throw new UnicornException("dvmClass=" + dvmClass);
                } else {
                    if (verbose) {
                        System.out.println(String.format("JNIEnv->SetStaticLongField(%s, %s, %d) was called", dvmClass.value, dvmField.fieldName, value));
                    }
                    dvmField.setStaticLongField(value);
                }
                return 0;
            }
        });

        Pointer _GetStringUTFLength = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                DvmObject<?> string = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).toUIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("GetStringUTFLength string=" + string + ", lr=" + UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                }
                String value = (String) string.getValue();
                if (verbose) {
                    System.out.println(String.format("JNIEnv->GetStringUTFLength(%s) was called", value));
                }
                byte[] data = value.getBytes(StandardCharsets.UTF_8);
                return data.length;
            }
        });

        Pointer _GetStringUTFChars = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                StringObject string = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).toUIntPeer());
                Pointer isCopy = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (isCopy != null) {
                    isCopy.setInt(0, JNI_TRUE);
                }
                String value = string.getValue();
                if (verbose) {
                    System.out.println(String.format("JNIEnv->GetStringUtfChars(%s, %s) was called", value, isCopy));
                }
                byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
                if (log.isDebugEnabled()) {
                    log.debug("GetStringUTFChars string=" + string + ", isCopy=" + isCopy + ", value=" + value + ", lr=" + UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                }
                byte[] data = Arrays.copyOf(bytes, bytes.length + 1);
                MemoryBlock memoryBlock = emulator.getMemory().malloc(data.length);
                memoryBlock.getPointer().write(0, data, 0, data.length);
                string.memoryBlock = memoryBlock;
                return memoryBlock.getPointer().toUIntPeer();
            }
        });

        Pointer _ReleaseStringUTFChars = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                StringObject string = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).toUIntPeer());
                Pointer pointer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (log.isDebugEnabled()) {
                    log.debug("ReleaseStringUTFChars string=" + string + ", pointer=" + pointer + ", lr=" + UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                }
                if (string.memoryBlock != null && string.memoryBlock.isSame(pointer)) {
                    string.memoryBlock.free(true);
                    string.memoryBlock = null;
                }
                return 0;
            }
        });

        Pointer _GetArrayLength = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer pointer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                Array<?> array = getObject(pointer.toUIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("GetArrayLength array=" + array + ", lr=" + UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                }
                if (verbose) {
                    System.out.println(String.format("JNIEnv->GetArrayLength(%s) was called", array));
                }
                return array.length();
            }
        });

        Pointer _NewObjectArray = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                Arm32RegisterContext context = emulator.getContext();
                int size = context.getR1Int();
                UnicornPointer elementClass = context.getR2Pointer();
                UnicornPointer initialElement = context.getR3Pointer();
                if (log.isDebugEnabled()) {
                    log.debug("NewObjectArray size=" + size + ", elementClass=" + elementClass + ", initialElement=" + initialElement);
                }
                DvmClass dvmClass = classMap.get(elementClass.toUIntPeer());
                if (dvmClass == null) {
                    throw new UnicornException("elementClass=" + elementClass);
                }

                DvmObject<?> obj = getObject(initialElement.toUIntPeer());
                DvmObject<?>[] array = new DvmObject[size];
                for (int i = 0; i < size; i++) {
                    array[i] = new DvmObject<>(dvmClass, obj);
                }

                return addObject(new ArrayObject(array), false);
            }
        });

        Pointer _GetObjectArrayElement = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                ArrayObject array = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).toUIntPeer());
                int index = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("GetObjectArrayElement array=" + array + ", index=" + index);
                }
                if (verbose) {
                    System.out.println(String.format("JNIEnv->GetObjectArrayElement(%s, %d) was called", array, index));
                }
                return addObject(array.getValue()[index], false);
            }
        });

        Pointer _SetObjectArrayElement = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                ArrayObject array = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).toUIntPeer());
                int index = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
                DvmObject<?> obj = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3).toUIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("setObjectArrayElement array=" + array + ", index=" + index + ", obj=" + obj);
                }
                DvmObject<?>[] objs = array.getValue();
                objs[index]=obj;
                return 0;
            }
        });

        Pointer _NewFloatArray = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                int size = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("NewByteArray size=" + size);
                }
                if (verbose) {
                    System.out.println(String.format("JNIEnv->NewFloatArray(%d) was called", size));
                }
                return addObject(new FloatArray(new float[size]), false);
            }
        });

        Pointer _GetFloatArrayElements = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                FloatArray array = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).toUIntPeer());
                Pointer isCopy = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                return array._GetArrayCritical(emulator, isCopy).toUIntPeer();
            }
        });
        
        Pointer _NewByteArray = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                Arm32RegisterContext ctx = emulator.getContext();
                int size = ctx.getR1Int();
                if (log.isDebugEnabled()) {
                    log.debug("NewByteArray size=" + size + ", LR=" + ctx.getLRPointer() + ", PC=" + UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_PC));
                }
                if (verbose) {
                    System.out.println(String.format("JNIEnv->NewByteArray(%d) was called", size));
                }
                return addObject(new ByteArray(new byte[size]), false);
            }
        });

        Pointer _NewIntArray = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                int size = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("NewIntArray size=" + size);
                }
                if (verbose) {
                    System.out.println(String.format("JNIEnv->NewIntArray(%d) was called", size));
                }
                return addObject(new IntArray(new int[size]), false);
            }
        });
        
        Pointer _NewDoubleArray = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                int size = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("_NewDoubleArray size=" + size);
                }
                if (verbose) {
                    System.out.println(String.format("JNIEnv->NewDoubleArray(%d) was called", size));
                }
                return addObject(new DoubleArray(new double[size]), false);
            }
        });

        Pointer _GetByteArrayElements = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                ByteArray array = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).toUIntPeer());
                Pointer isCopy = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (log.isDebugEnabled()) {
                    Inspector.inspect(array.value, "GetByteArrayElements array=" + array + ", isCopy=" + isCopy);
                }
                return array._GetArrayCritical(emulator, isCopy).toUIntPeer();
            }
        });

        Pointer _GetIntArrayElements = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                IntArray array = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).toUIntPeer());
                Pointer isCopy = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (log.isDebugEnabled()) {
                    log.debug("GetIntArrayElements array=" + array + ", isCopy=" + isCopy);
                }
                return array._GetArrayCritical(emulator, isCopy).toUIntPeer();
            }
        });

        Pointer _GetStringLength = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                DvmObject<?> string = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).toUIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("GetStringLength string=" + string + ", lr=" + UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                }
                String value = (String) string.getValue();
                return value.length();
            }
        });

        Pointer _GetStringChars = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                StringObject string = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).toUIntPeer());
                Pointer isCopy = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (isCopy != null) {
                    isCopy.setInt(0, JNI_TRUE);
                }
                String value = string.getValue();
                byte[] bytes = new byte[value.length() * 2];
                ByteBuffer buffer = ByteBuffer.wrap(bytes);
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                for (char c : value.toCharArray()) {
                    buffer.putChar(c);
                }
                if (log.isDebugEnabled()) {
                    log.debug("GetStringChars string=" + string + ", isCopy=" + isCopy + ", value=" + value + ", lr=" + UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                }
                byte[] data = Arrays.copyOf(bytes, bytes.length + 1);
                MemoryBlock memoryBlock = emulator.getMemory().malloc(data.length);
                memoryBlock.getPointer().write(0, data, 0, data.length);
                string.memoryBlock = memoryBlock;
                return memoryBlock.getPointer().toUIntPeer();
            }
        });

        Pointer _ReleaseStringChars = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                StringObject string = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).toUIntPeer());
                Pointer pointer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (log.isDebugEnabled()) {
                    log.debug("ReleaseStringChars string=" + string + ", pointer=" + pointer + ", lr=" + UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                }
                if (string.memoryBlock != null && string.memoryBlock.isSame(pointer)) {
                    string.memoryBlock.free(true);
                    string.memoryBlock = null;
                }
                return 0;
            }
        });

        Pointer _NewStringUTF = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                Pointer bytes = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                String string = bytes.getString(0);
                if (log.isDebugEnabled()) {
                    log.debug("NewStringUTF bytes=" + bytes + ", string=" + string);
                }
                if (verbose) {
                    System.out.println(String.format("JNIEnv->NewStringUTF(%s, %s) was called", string, UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR)));
                }
                return addObject(new StringObject(DalvikVM.this, string), false);
            }
        });

        Pointer _ReleaseByteArrayElements = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                ByteArray array = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).toUIntPeer());
                Pointer pointer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                int mode = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("ReleaseByteArrayElements array=" + array + ", pointer=" + pointer + ", mode=" + mode);
                }
                array._ReleaseArrayCritical(pointer, mode);
                return 0;
            }
        });

        Pointer _ReleaseIntArrayElements = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                IntArray array = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).toUIntPeer());
                Pointer pointer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                int mode = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("ReleaseIntArrayElements array=" + array + ", pointer=" + pointer + ", mode=" + mode);
                }
                array._ReleaseArrayCritical(pointer, mode);
                return 0;
            }
        });

        Pointer _ReleaseFloatArrayElements = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                FloatArray array = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).toUIntPeer());
                Pointer pointer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                int mode = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("ReleaseByteArrayElements array=" + array + ", pointer=" + pointer + ", mode=" + mode);
                }
                array._ReleaseArrayCritical(pointer, mode);
                return 0;
            }
        });

        Pointer _GetByteArrayRegion = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                Unicorn u = emulator.getUnicorn();
                ByteArray array = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).toUIntPeer());
                int start = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
                int length = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
                Pointer buf = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_SP).getPointer(0);
                if (verbose) {
                    System.out.println(String.format("JNIEnv->GetByteArrayRegion(%s, %d, %d, %s) was called", array, start, length, buf));
                }
                byte[] data = Arrays.copyOfRange(array.value, start, start + length);
                if (log.isDebugEnabled()) {
                    Inspector.inspect(data, "GetByteArrayRegion array=" + array + ", start=" + start + ", length=" + length + ", buf=" + buf);
                }
                buf.write(0, data, 0, data.length);
                return 0;
            }
        });

        Pointer _SetByteArrayRegion = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                Unicorn u = emulator.getUnicorn();
                ByteArray array = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).toUIntPeer());
                int start = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
                int len = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
                Pointer buf = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_SP).getPointer(0);
                if (verbose) {
                    System.out.println(String.format("JNIEnv->SetByteArrayRegion(%s, %d, %d, %s) was called", array, start, len, buf));
                }
                byte[] data = buf.getByteArray(0, len);
                if (log.isDebugEnabled()) {
                    if (data.length > 1024) {
                        Inspector.inspect(Arrays.copyOf(data, 1024), "SetByteArrayRegion array=" + array + ", start=" + start + ", len=" + len + ", buf=" + buf);
                    } else {
                        Inspector.inspect(data, "SetByteArrayRegion array=" + array + ", start=" + start + ", len=" + len + ", buf=" + buf);
                    }
                }
                array.setData(start, data);
                return 0;
            }
        });
        
        Pointer _SetIntArrayRegion = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                Unicorn u = emulator.getUnicorn();
                IntArray array = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).toUIntPeer());
                int start = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
                int len = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
                Pointer buf = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_SP).getPointer(0);
                int[] data = buf.getIntArray(0, len);
                if (log.isDebugEnabled()) {
                    log.debug("SetIntArrayRegion array=" + array + ", start=" + start + ", len=" + len + ", buf=" + buf);
                }
                array.setData(start, data);
                return 0;
            }
        });

        Pointer _SetFloatArrayRegion = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                Unicorn u = emulator.getUnicorn();
                FloatArray array = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).toUIntPeer());
                int start = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
                int len = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
                Pointer buf = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_SP).getPointer(0);
                float[] data = buf.getFloatArray(0, len);
                if (log.isDebugEnabled()) {
                    log.debug("SetIntArrayRegion array=" + array + ", start=" + start + ", len=" + len + ", buf=" + buf);
                }
                array.setData(start, data);
                return 0;
            }
        });
        
        Pointer _SetDoubleArrayRegion = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                Unicorn u = emulator.getUnicorn();
                DoubleArray array = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).toUIntPeer());
                int start = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
                int len = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
                Pointer buf = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_SP).getPointer(0);
                double[] data = buf.getDoubleArray(0, len);
                if (log.isDebugEnabled()) {
                    log.debug("SetDoubleArrayRegion array=" + array + ", start=" + start + ", len=" + len + ", buf=" + buf);
                }
                array.setData(start, data);
                return 0;
            }
        });

        Pointer _RegisterNatives = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                Unicorn u = emulator.getUnicorn();
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                Pointer methods = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                int nMethods = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("RegisterNatives dvmClass=" + dvmClass + ", methods=" + methods + ", nMethods=" + nMethods);
                }
                if (verbose) {
                    System.out.println(String.format("JNIEnv->RegisterNatives(%s, %s, %d) was called", dvmClass.value, methods, nMethods));
                }
                for (int i = 0; i < nMethods; i++) {
                    Pointer method = methods.share(i * 0xc);
                    Pointer name = method.getPointer(0);
                    Pointer signature = method.getPointer(4);
                    Pointer fnPtr = method.getPointer(8);
                    String methodName = name.getString(0);
                    String signatureValue = signature.getString(0);
                    if (log.isDebugEnabled()) {
                        log.debug("RegisterNatives dvmClass=" + dvmClass + ", name=" + methodName + ", signature=" + signatureValue + ", fnPtr=" + fnPtr);
                    }
                    dvmClass.nativesMap.put(methodName + signatureValue, (UnicornPointer) fnPtr);

                    if (verbose) {
                        System.out.println(String.format("RegisterNative(%s, %s%s, %s)", dvmClass.value, methodName, signatureValue, fnPtr));
                    }
                }
                return JNI_OK;
            }
        });

        Pointer _GetJavaVM = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer vm = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                if (log.isDebugEnabled()) {
                    log.debug("GetJavaVM vm=" + vm);
                }
                vm.setPointer(0, _JavaVM);
                return JNI_OK;
            }
        });

        Pointer _GetPrimitiveArrayCritical = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                PrimitiveArray<?> array = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).toUIntPeer());
                Pointer isCopy = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (log.isDebugEnabled()) {
                    log.debug("GetPrimitiveArrayCritical array=" + array + ", isCopy=" + isCopy);
                }
                return array._GetArrayCritical(emulator, isCopy).toUIntPeer();
            }
        });

        Pointer _ReleasePrimitiveArrayCritical = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                PrimitiveArray<?> array = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).toUIntPeer());
                Pointer pointer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                int mode = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("ReleasePrimitiveArrayCritical array=" + array + ", pointer=" + pointer + ", mode=" + mode);
                }
                array._ReleaseArrayCritical(pointer, mode);
                return 0;
            }
        });

        Pointer _ExceptionCheck = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                if (log.isDebugEnabled()) {
                    log.debug("ExceptionCheck throwable=" + throwable);
                }
                return throwable == null ? JNI_FALSE : JNI_TRUE;
            }
        });

        Pointer _GetObjectRefType = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                DvmObject<?> dvmGlobalObject = globalObjectMap.get(object.toUIntPeer());
                DvmObject<?> dvmLocalObject = localObjectMap.get(object.toUIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("GetObjectRefType object=" + object + ", dvmGlobalObject=" + dvmGlobalObject + ", dvmLocalObject=" + dvmLocalObject);
                }
                if (dvmGlobalObject != null) {
                    return JNIGlobalRefType;
                } else if(dvmLocalObject != null) {
                    return JNILocalRefType;
                } else {
                    return JNIInvalidRefType;
                }
            }
        });

        final UnicornPointer impl = svcMemory.allocate(0x3a4 + emulator.getPointerSize(), "JNIEnv.impl");
        for (int i = 0; i < 0x3a4; i += 4) {
            impl.setInt(i, i);
        }
        impl.setPointer(0x18, _FindClass);
        impl.setPointer(0x24, _ToReflectedMethod);
        impl.setPointer(0x34, _Throw);
        impl.setPointer(0x3c, _ExceptionOccurred);
        impl.setPointer(0x44, _ExceptionClear);
        impl.setPointer(0x4c, _PushLocalFrame);
        impl.setPointer(0x50, _PopLocalFrame);
        impl.setPointer(0x54, _NewGlobalRef);
        impl.setPointer(0x58, _DeleteGlobalRef);
        impl.setPointer(0x5C, _DeleteLocalRef);
        impl.setPointer(0x60, _IsSameObject);
        impl.setPointer(0x64, _NewLocalRef);
        impl.setPointer(0x68, _EnsureLocalCapacity);
        impl.setPointer(0x70, _NewObject);
        impl.setPointer(0x74, _NewObjectV);
        impl.setPointer(0x7c, _GetObjectClass);
        impl.setPointer(0x80, _IsInstanceOf);
        impl.setPointer(0x84, _GetMethodID);
        impl.setPointer(0x88, _CallObjectMethod);
        impl.setPointer(0x8c, _CallObjectMethodV);
        impl.setPointer(0x94, _CallBooleanMethod);
        impl.setPointer(0x98, _CallBooleanMethodV);
        impl.setPointer(0xc4, _CallIntMethod);
        impl.setPointer(0xc8, _CallIntMethodV);
        impl.setPointer(0xd4, _CallLongMethodV);
        impl.setPointer(0xe0, _CallFloatMethodV);
        impl.setPointer(0xf4, _CallVoidMethod);
        impl.setPointer(0xf8, _CallVoidMethodV);
        impl.setPointer(0x178, _GetFieldID);
        impl.setPointer(0x17c, _GetObjectField);
        impl.setPointer(0x180, _GetBooleanField);
        impl.setPointer(0x190, _GetIntField);
        impl.setPointer(0x194, _GetLongField);
        impl.setPointer(0x1a0, _SetObjectField);
        impl.setPointer(0x1a4, _SetBooleanField);
        impl.setPointer(0x1b4, _SetIntField);
        impl.setPointer(0x1b8, _SetLongField);
        impl.setPointer(0x1c0, _SetDoubleField);
        impl.setPointer(0x1c4, _GetStaticMethodID);
        impl.setPointer(0x1c8, _CallStaticObjectMethod);
        impl.setPointer(0x1cc, _CallStaticObjectMethodV);
        impl.setPointer(0x1d4, _CallStaticBooleanMethod);
        impl.setPointer(0x1d8, _CallStaticBooleanMethodV);
        impl.setPointer(0x204, _CallStaticIntMethod);
        impl.setPointer(0x208, _CallStaticIntMethodV);
        impl.setPointer(0x210, _CallStaticLongMethod);
        impl.setPointer(0x214, _CallStaticLongMethodV);
        impl.setPointer(0x234, _CallStaticVoidMethod);
        impl.setPointer(0x238, _CallStaticVoidMethodV);
        impl.setPointer(0x240, _GetStaticFieldID);
        impl.setPointer(0x244, _GetStaticObjectField);
        impl.setPointer(0x258, _GetStaticIntField);
        impl.setPointer(0x25c, _GetStaticLongField);
        impl.setPointer(0x280, _SetStaticLongField);
        impl.setPointer(0x290, _GetStringLength);
        impl.setPointer(0x294, _GetStringChars);
        impl.setPointer(0x298, _ReleaseStringChars);
        impl.setPointer(0x29c, _NewStringUTF);
        impl.setPointer(0x2a0, _GetStringUTFLength);
        impl.setPointer(0x2a4, _GetStringUTFChars);
        impl.setPointer(0x2a8, _ReleaseStringUTFChars);
        impl.setPointer(0x2ac, _GetArrayLength);
        impl.setPointer(0x2b0, _NewObjectArray);
        impl.setPointer(0x2c0, _NewByteArray);
        impl.setPointer(0x2cc, _NewIntArray);
        impl.setPointer(0x2d8, _NewDoubleArray);
        impl.setPointer(0x2e0, _GetByteArrayElements);
        impl.setPointer(0x2ec, _GetIntArrayElements);
        impl.setPointer(0x2b4, _GetObjectArrayElement);
        impl.setPointer(0x2b8, _SetObjectArrayElement);
        impl.setPointer(0x2d4, _NewFloatArray);
        impl.setPointer(0x2f4, _GetFloatArrayElements);
        impl.setPointer(0x300, _ReleaseByteArrayElements);
        impl.setPointer(0x30c, _ReleaseIntArrayElements);
        impl.setPointer(0x314, _ReleaseFloatArrayElements);
        impl.setPointer(0x320, _GetByteArrayRegion);
        impl.setPointer(0x340, _SetByteArrayRegion);
        impl.setPointer(0x34c, _SetIntArrayRegion);
        impl.setPointer(0x354, _SetFloatArrayRegion);
        impl.setPointer(0x358, _SetDoubleArrayRegion);
        impl.setPointer(0x35c, _RegisterNatives);
        impl.setPointer(0x36c, _GetJavaVM);
        impl.setPointer(0x378, _GetPrimitiveArrayCritical);
        impl.setPointer(0x37c, _ReleasePrimitiveArrayCritical);
        impl.setPointer(0x390, _ExceptionCheck);
        impl.setPointer(0x3a0, _GetObjectRefType);

        _JNIEnv = svcMemory.allocate(emulator.getPointerSize(), "_JNIEnv");
        _JNIEnv.setPointer(0, impl);

        UnicornPointer _AttachCurrentThread = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                Pointer vm = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                Pointer env = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                Pointer args = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2); // JavaVMAttachArgs*
                if (log.isDebugEnabled()) {
                    log.debug("AttachCurrentThread vm=" + vm + ", env=" + env.getPointer(0) + ", args=" + args);
                }
                env.setPointer(0, _JNIEnv);
                return JNI_OK;
            }
        });

        UnicornPointer _GetEnv = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator emulator) {
                Pointer vm = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                Pointer env = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                int version = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("GetEnv vm=" + vm + ", env=" + env.getPointer(0) + ", version=0x" + Integer.toHexString(version));
                }
                env.setPointer(0, _JNIEnv);
                return JNI_OK;
            }
        });

        UnicornPointer _JNIInvokeInterface = svcMemory.allocate(emulator.getPointerSize() * 8, "_JNIInvokeInterface");
        for (int i = 0; i < emulator.getPointerSize() * 8; i += emulator.getPointerSize()) {
            _JNIInvokeInterface.setInt(i, i);
        }
        _JNIInvokeInterface.setPointer(emulator.getPointerSize() * 4, _AttachCurrentThread);
        _JNIInvokeInterface.setPointer(emulator.getPointerSize() * 6, _GetEnv);

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

    byte[] findLibrary(ApkFile apkFile, String soName) throws IOException {
        byte[] soData = apkFile.getFileData("lib/armeabi-v7a/" + soName);
        if (soData != null) {
            log.debug("resolve armeabi-v7a library: " + soName);
            return soData;
        }
        soData = apkFile.getFileData("lib/armeabi/" + soName);
        if (soData != null) {
            log.debug("resolve armeabi library: " + soName);
        }
        return soData;
    }
}
