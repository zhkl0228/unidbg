package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;
import java.util.List;

import static de.fearlesstobi.demangler.util.StringUtil.nodeListToArray;

public class TemplateArguments extends NodeArray {
    public TemplateArguments(List<BaseNode> nodes) {
        super(nodes, NodeType.TemplateArguments);
    }

    @Override
    public void printLeft(StringWriter writer) {
        String params = String.join(", ", nodeListToArray(nodes));

        writer.write("<");

        writer.write(params);

        if (params.endsWith(">")) {
            writer.write(" ");
        }

        writer.write(">");
    }
}