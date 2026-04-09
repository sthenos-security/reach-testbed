// Fixture: code_patch · CWE-502 Deserialization · Java
// VERDICT: TRUE_POSITIVE
// PATTERN: raw_readobject_no_validation
// SOURCE: network_stream
// SINK: ObjectInputStream.readObject
// TAINT_HOPS: 1
// NOTES: No whitelist, no class validation — classic deser RCE
import java.io.*;

public class TpUnsafeDeserialization {
    public Object unsafeDeserialize(InputStream input) throws Exception {
        // VULNERABLE: no whitelist validation
        ObjectInputStream ois = new ObjectInputStream(input);
        return ois.readObject();
    }
}
