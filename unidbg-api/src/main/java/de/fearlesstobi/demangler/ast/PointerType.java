package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class PointerType extends BaseNode {
    private final BaseNode child;

    public PointerType(BaseNode child) {
        super(NodeType.PointerType);
        this.child = child;
    }

    @Override
    public boolean hasRightPart() {
        return child.hasRightPart();
    }

    @Override
    public void printLeft(StringWriter writer) {
        child.printLeft(writer);
        if (child.isArray()) {
            writer.write(" ");
        }

        if (child.isArray() || child.hasFunctions()) {
            writer.write("(");
        }

        writer.write("*");
    }

    @Override
    public void printRight(StringWriter writer) {
        if (child.isArray() || child.hasFunctions()) {
            writer.write(")");
        }

        child.printRight(writer);
    }
}