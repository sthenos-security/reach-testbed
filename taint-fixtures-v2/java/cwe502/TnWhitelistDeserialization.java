// Fixture: code_patch · CWE-502 Deserialization · Java
// VERDICT: TRUE_NEGATIVE
// PATTERN: whitelist_resolve_class
// SOURCE: network_stream
// SINK: ObjectInputStream.readObject
// TAINT_HOPS: 1
// NOTES: Elasticsearch-style — resolveClass override with class/package whitelist
// REAL_WORLD: elastic/elasticsearch ThrowableObjectInputStream (commit bf3052d)
import java.io.*;
import java.util.*;

public class TnWhitelistDeserialization {
    private static final Set<String> PKG_WHITELIST = Set.of(
        "java.lang", "java.util", "org.elasticsearch"
    );

    public Object safeDeserialize(InputStream in) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in) {
            @Override
            protected Class<?> resolveClass(ObjectStreamClass desc)
                    throws IOException, ClassNotFoundException {
                Class<?> clazz = super.resolveClass(desc);
                String name = clazz.getName();
                boolean allowed = PKG_WHITELIST.stream().anyMatch(name::startsWith);
                if (!allowed) throw new InvalidClassException("Blocked: " + name);
                return clazz;
            }
        };
        return ois.readObject();
    }
}
