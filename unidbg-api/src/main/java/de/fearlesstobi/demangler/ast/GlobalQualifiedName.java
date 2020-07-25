package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class GlobalQualifiedName extends ParentNode {
    public GlobalQualifiedName(BaseNode child) {
        super(NodeType.GlobalQualifiedName, child);
    }

    @Override
    public void printLeft(StringWriter writer) {
        writer.write("::");
        child.print(writer);
    }
}
