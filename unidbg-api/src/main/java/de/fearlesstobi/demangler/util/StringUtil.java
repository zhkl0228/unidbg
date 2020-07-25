package de.fearlesstobi.demangler.util;

import de.fearlesstobi.demangler.ast.BaseNode;

import java.util.LinkedList;
import java.util.List;

public class StringUtil {

    public static String[] nodeListToArray(List<BaseNode> nodes) {
        List<String> nodeStrings = new LinkedList<>();
        for (BaseNode node : nodes) {
            nodeStrings.add(node.toString());
        }
        return nodeStrings.toArray(new String[0]);
    }

}
