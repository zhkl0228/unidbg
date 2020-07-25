package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class QualifiedName extends BaseNode {
    private final BaseNode qualifier;
    private final BaseNode name;

    public QualifiedName(BaseNode qualifier, BaseNode name) {
        super(NodeType.QualifiedName);
        this.qualifier = qualifier;
        this.name = name;
    }

    @Override
    public void printLeft(StringWriter writer) {
        qualifier.print(writer);
        writer.write("::");
        name.print(writer);
    }
}