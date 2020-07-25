package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class DynamicExceptionSpec extends ParentNode {
    public DynamicExceptionSpec(BaseNode child) {
        super(NodeType.DynamicExceptionSpec, child);
    }

    @Override
    public void printLeft(StringWriter writer) {
        writer.write("throw(");
        child.print(writer);
        writer.write(")");
    }
}