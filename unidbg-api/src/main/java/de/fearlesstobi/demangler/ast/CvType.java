package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class CvType extends ParentNode {

    public class Cv {
        public static final int None = 0;
        public static final int Const = 1;
        public static final int Volatile = 2;
        public static final int Restricted = 4;
    }

    private final int qualifier;

    public CvType(int qualifier, BaseNode child) {
        super(NodeType.CvQualifierType, child);
        this.qualifier = qualifier;
    }

    private void PrintQualifier(StringWriter writer) {
        if ((qualifier & Cv.Const) != 0) {
            writer.write(" const");
        }

        if ((qualifier & Cv.Volatile) != 0) {
            writer.write(" volatile");
        }

        if ((qualifier & Cv.Restricted) != 0) {
            writer.write(" restrict");
        }
    }

    @Override
    public void printLeft(StringWriter writer) {
        if (child != null) {
            child.printLeft(writer);
        }

        PrintQualifier(writer);
    }

    @Override
    public boolean hasRightPart() {
        return child != null && child.hasRightPart();
    }

    @Override
    public void printRight(StringWriter writer) {
        if (child != null) {
            child.printRight(writer);
        }
    }
}