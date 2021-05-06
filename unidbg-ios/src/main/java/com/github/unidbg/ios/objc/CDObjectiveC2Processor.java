package com.github.unidbg.ios.objc;

import io.kaitai.MachO;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

public class CDObjectiveC2Processor extends CDObjectiveCProcessor {

    private final Map<String, MachO.SegmentCommand64.Section64> objcSections;

    public CDObjectiveC2Processor(ByteBuffer buffer, Map<String, MachO.SegmentCommand64.Section64> objcSections) {
        super(buffer);
        this.objcSections = objcSections;

        load();
    }

    private final Map<Long, Objc2Class> classMap = new HashMap<>();

    @Override
    void loadClasses() {
        MachO.SegmentCommand64.Section64 section = objcSections.get("__objc_classlist");
        if (section == null) {
            return;
        }
        MachO.SegmentCommand64.Section64.PointerList pointerList = (MachO.SegmentCommand64.Section64.PointerList) section.data();
        for (long item : pointerList.items()) {
            Objc2Class objc2Class = Objc2Class.read(classMap, buffer, item);
            if (objc2Class != null) {
                objc2Class.readMetaClass(classMap, buffer);
                classList.add(objc2Class);
            }
        }
    }

    @Override
    void loadCategories() {
        MachO.SegmentCommand64.Section64 section = objcSections.get("__objc_catlist");
        if (section == null) {
            return;
        }
        MachO.SegmentCommand64.Section64.PointerList pointerList = (MachO.SegmentCommand64.Section64.PointerList) section.data();
        for (long item : pointerList.items()) {
            Objc2Category category = Objc2Category.read(classMap, buffer, item);
            categoryList.add(category);
        }
    }
}
