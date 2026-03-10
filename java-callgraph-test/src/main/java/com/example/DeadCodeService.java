package com.example;

import org.apache.commons.text.StringSubstitutor;

import java.util.Map;

/**
 * NOT_REACHABLE: commons-text CVE-2022-42889 (Text4Shell)
 *
 * This class is NEVER instantiated or called from any Spring component,
 * controller, or service. It exists so that Grype finds commons-text in
 * the SBOM, but the Java call graph must determine it is dead code.
 *
 * CANARY TEST:
 *   - If commons-text CVE shows NOT_REACHABLE → Java call graph ran correctly.
 *   - If commons-text CVE shows UNKNOWN       → Java call graph did NOT run.
 *
 * CVE-2022-42889: StringSubstitutor.replace() performs DNS/script lookups
 * on interpolated expressions like ${script:javascript:...} or ${dns:...}
 * when DefaultStringLookup is on the classpath (default in 1.9).
 */
public class DeadCodeService {

    // Never instantiated — no @Service annotation, no @Autowired, no new DeadCodeService()
    // anywhere in the codebase.

    /**
     * Dead-code method. If this were called with attacker-controlled input:
     *   processTemplate("${script:javascript:java.lang.Runtime.getRuntime().exec('id')}")
     * it would achieve RCE via Text4Shell.
     */
    public String processTemplate(String template) {
        // CVE-2022-42889: StringSubstitutor.replace() evaluates script: and dns: lookups.
        Map<String, String> vars = Map.of("app", "testbed");
        StringSubstitutor sub = new StringSubstitutor(vars);
        return sub.replace(template);
    }

    /**
     * Another dead-code path using the static convenience method.
     */
    public static String expandVars(String input) {
        // Also vulnerable — same underlying DefaultStringLookup evaluation.
        return StringSubstitutor.replaceSystemProperties(input);
    }
}
