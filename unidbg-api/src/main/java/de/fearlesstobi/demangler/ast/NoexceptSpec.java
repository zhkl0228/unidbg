package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class NoexceptSpec extends ParentNode {
    public NoexceptSpec(BaseNode child) {
        super(NodeType.NoexceptSpec, child);
    }

    @Override
    public void printLeft(StringWriter writer) {
        writer.write("noexcept(");
        child.print(writer);
        writer.write(")");
    }
}
