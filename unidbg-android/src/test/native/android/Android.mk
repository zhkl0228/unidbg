LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := test
LOCAL_SRC_FILES := test.cpp
LOCAL_MODULE_PATH += $(LOCAL_PATH)
LOCAL_CPPFLAGS += -fexceptions
include $(BUILD_EXECUTABLE)
