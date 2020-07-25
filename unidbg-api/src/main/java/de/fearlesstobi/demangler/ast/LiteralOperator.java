package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class LiteralOperator extends ParentNode {
    public LiteralOperator(BaseNode child) {
        super(NodeType.LiteralOperator, child);
    }

    @Override
    public void printLeft(StringWriter writer) {
        writer.write("operator \"");
        child.printLeft(writer);
        writer.write("\"");
    }
}