// Fixture: CWE-78 Command Injection - Java
// VERDICT: TRUE_POSITIVE
// PATTERN: processbuilder_cmd_exe_c
// SOURCE: function_parameter
// SINK: ProcessBuilder with cmd.exe /C
// TAINT_HOPS: 1
// NOTES: cmd.exe /C introduces shell interpretation even with ProcessBuilder
// REAL_WORLD: elastic/elasticsearch windows-service-cli/ProcrunCommand.java
import java.util.*;

public class TpProcessBuilderCmdExe {
    public Process runService(String serviceId, String action) throws Exception {
        List<String> cmd = new ArrayList<>();
        cmd.add("cmd.exe");
        cmd.add("/C");
        // VULNERABLE: cmd.exe /C interprets shell metacharacters in serviceId
        cmd.add("service-" + serviceId + ".exe " + action);
        return new ProcessBuilder(cmd).start();
    }
}
