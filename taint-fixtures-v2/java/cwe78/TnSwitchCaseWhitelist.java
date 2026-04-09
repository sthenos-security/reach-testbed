// Fixture: code_patch · CWE-78 Command Injection · Java
// VERDICT: TRUE_NEGATIVE
// PATTERN: switch_case_command_whitelist
// SOURCE: function_parameter
// SINK: internal_dispatch
// TAINT_HOPS: 1
// NOTES: Only hardcoded cases executed — no shell invocation
public class TnSwitchCaseWhitelist {
    public void executeCommand(String command) {
        switch (command) {
            case "gc": System.gc(); break;
            case "version": System.getProperty("java.version"); break;
            default: throw new IllegalArgumentException("Unknown: " + command);
        }
    }
}
