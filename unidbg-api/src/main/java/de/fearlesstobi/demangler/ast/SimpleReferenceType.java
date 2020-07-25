package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class SimpleReferenceType extends ParentNode {
    public final int qualifier;

    public SimpleReferenceType(int qualifier, BaseNode child) {
        super(NodeType.SimpleReferenceType, child);
        this.qualifier = qualifier;
    }

    public void PrintQualifier(StringWriter writer) {
        if ((qualifier & Reference.LValue) != 0) {
            writer.write("&");
        }

        if ((qualifier & Reference.RValue) != 0) {
            writer.write("&&");
        }
    }

    @Override
    public void printLeft(StringWriter writer) {
        if (child != null) {
            child.printLeft(writer);
        } else if (qualifier != Reference.None) {
            writer.write(" ");
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
