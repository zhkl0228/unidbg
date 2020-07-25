package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class NameType extends BaseNode {
    private final String nameValue;

    public NameType(String nameValue, NodeType type) {
        super(type);
        this.nameValue = nameValue;
    }

    public NameType(String nameValue) {
        super(NodeType.NameType);
        this.nameValue = nameValue;
    }

    @Override
    public String getName() {
        return nameValue;
    }

    @Override
    public void printLeft(StringWriter writer) {
        writer.write(nameValue);
    }
}