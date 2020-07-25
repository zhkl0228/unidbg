package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class ReferenceType extends BaseNode {
    private final String reference;
    private final BaseNode child;

    public ReferenceType(String reference, BaseNode child) {
        super(NodeType.ReferenceType);
        this.reference = reference;
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

        writer.write(reference);
    }

    @Override
    public void printRight(StringWriter writer) {
        if (child.isArray() || child.hasFunctions()) {
            writer.write(")");
        }

        child.printRight(writer);
    }
}