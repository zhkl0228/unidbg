package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class DtorName extends ParentNode {
    public DtorName(BaseNode name) {
        super(NodeType.DtOrName, name);
    }

    @Override
    public void printLeft(StringWriter writer) {
        writer.write("~");
        child.printLeft(writer);
    }
}