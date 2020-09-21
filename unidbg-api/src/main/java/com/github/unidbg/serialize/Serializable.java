package com.github.unidbg.serialize;

import java.io.DataOutput;
import java.io.IOException;

public interface Serializable {

    void serialize(DataOutput out) throws IOException;

}
