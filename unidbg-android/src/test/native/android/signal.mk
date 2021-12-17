LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := signal
LOCAL_SRC_FILES := signal.c
LOCAL_MODULE_PATH += $(LOCAL_PATH)
LOCAL_CFLAGS += -std=c99
LOCAL_LDFLAGS += -pthread
include $(BUILD_EXECUTABLE)
