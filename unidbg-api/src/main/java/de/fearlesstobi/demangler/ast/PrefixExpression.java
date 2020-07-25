package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class PrefixExpression extends ParentNode {
    private final String prefix;

    public PrefixExpression(String prefix, BaseNode child) {
        super(NodeType.PrefixExpression, child);
        this.prefix = prefix;
    }

    @Override
    public void printLeft(StringWriter writer) {
        writer.write(prefix);
        writer.write("(");
        child.print(writer);
        writer.write(")");
    }
}