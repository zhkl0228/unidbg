package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class SpecialName extends ParentNode {
    private final String specialValue;

    public SpecialName(String specialValue, BaseNode type) {
        super(NodeType.SpecialName, type);
        this.specialValue = specialValue;
    }

    @Override
    public void printLeft(StringWriter writer) {
        writer.write(specialValue);
        child.print(writer);
    }
}