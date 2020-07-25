package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class StdQualifiedName extends ParentNode {
    public StdQualifiedName(BaseNode child) {
        super(NodeType.StdQualifiedName, child);
    }

    @Override
    public void printLeft(StringWriter writer) {
        writer.write("std::");
        child.print(writer);
    }
}
