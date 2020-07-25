package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class NestedName extends ParentNode {
    private final BaseNode name;

    public NestedName(BaseNode name, BaseNode type) {
        super(NodeType.NestedName, type);
        this.name = name;
    }

    @Override
    public String getName() {
        return name.getName();
    }

    @Override
    public void printLeft(StringWriter writer) {
        child.print(writer);
        writer.write("::");
        name.print(writer);
    }
}