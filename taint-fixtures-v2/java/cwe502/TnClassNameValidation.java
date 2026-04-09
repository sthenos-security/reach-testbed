// Fixture: code_patch · CWE-502 Deserialization · Java
// VERDICT: TRUE_NEGATIVE
// PATTERN: classname_allowlist_before_deser
// SOURCE: function_parameter
// SINK: ObjectInputStream.readObject
// TAINT_HOPS: 1
// NOTES: Class name validated against allowlist before deserialization
import java.io.*;
import java.util.*;

public class TnClassNameValidation {
    private static final Set<String> ALLOWED = Set.of(
        "java.lang.String", "java.util.ArrayList", "java.util.HashMap"
    );

    public Object safeDeserialize(byte[] data, String className) throws Exception {
        if (!ALLOWED.contains(className)) {
            throw new SecurityException("Class not allowed: " + className);
        }
        return new ObjectInputStream(new ByteArrayInputStream(data)).readObject();
    }
}
