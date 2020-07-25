package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class CtorDtorNameType extends ParentNode {
    private final boolean isDestructor;

    public CtorDtorNameType(BaseNode name, boolean isDestructor) {
        super(NodeType.CtorDtorNameType, name);
        this.isDestructor = isDestructor;
    }

    @Override
    public void printLeft(StringWriter writer) {
        if (isDestructor) {
            writer.write("~");
        }

        writer.write(child.getName());
    }
}