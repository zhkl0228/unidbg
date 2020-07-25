package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public abstract class BaseNode {
    public NodeType type;

    BaseNode(NodeType type) {
        this.type = type;
    }

    //virtual
    public void print(StringWriter writer) {
        printLeft(writer);

        if (hasRightPart()) {
            printRight(writer);
        }
    }

    protected abstract void printLeft(StringWriter writer);

    //virtual
    boolean hasRightPart() {
        return false;
    }

    //virtual
    boolean isArray() {
        return false;
    }

    //virtual
    boolean hasFunctions() {
        return false;
    }

    //virtual
    String getName() {
        return null;
    }

    //virtual
    void printRight(StringWriter writer) {
    }

    @Override
    public String toString() {
        StringWriter writer = new StringWriter();

        print(writer);

        return writer.toString();
    }
}