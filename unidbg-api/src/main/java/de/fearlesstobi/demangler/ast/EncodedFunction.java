package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class EncodedFunction extends BaseNode {
    private final BaseNode name;
    private final BaseNode params;
    private final BaseNode cv;
    private final BaseNode ref;
    private final BaseNode attrs;
    private final BaseNode ret;

    public EncodedFunction(BaseNode name, BaseNode params, BaseNode cv, BaseNode ref, BaseNode attrs, BaseNode ret) {
        super(NodeType.NameType);
        this.name = name;
        this.params = params;
        this.cv = cv;
        this.ref = ref;
        this.attrs = attrs;
        this.ret = ret;
    }

    @Override
    public void printLeft(StringWriter writer) {
        if (ret != null) {
            ret.printLeft(writer);

            if (!ret.hasRightPart()) {
                writer.write(" ");
            }
        }

        name.print(writer);

    }

    @Override
    public boolean hasRightPart() {
        return true;
    }

    @Override
    public void printRight(StringWriter writer) {
        writer.write("(");

        if (params != null) {
            params.print(writer);
        }

        writer.write(")");

        if (ret != null) {
            ret.printRight(writer);
        }

        if (cv != null) {
            cv.print(writer);
        }

        if (ref != null) {
            ref.print(writer);
        }

        if (attrs != null) {
            attrs.print(writer);
        }
    }
}