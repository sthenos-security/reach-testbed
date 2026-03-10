package com.example;

import org.apache.commons.text.StringSubstitutor;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

/**
 * UNKNOWN signals — this @RestController IS instantiated by Spring (so it's on the
 * call graph) but the VULNERABLE methods are never called from any client code path.
 *
 * Spring controllers are entrypoints themselves, so any @RequestMapping here IS reachable.
 * The UNKNOWN pattern for Java is therefore: the class is on the classpath and Spring
 * instantiates it, but the specific vulnerable method is not mapped to any HTTP route —
 * i.e. it's a private/package-private helper that's never called.
 *
 * CVE-2022-42889 (commons-text): StringSubstitutor.replace() with user input —
 *   expandVarsUnknown() is a private method never called from any @RequestMapping.
 * CWE-326 (weak key): generateWeakKeyUnknown() — private, not on HTTP path.
 * DLP: exportPiiUnknown() — private, not on HTTP path.
 * AI: callLlmUnknown() — private, not on HTTP path.
 * SECRET: internalKey used only in private method.
 */
@RestController
@RequestMapping("/api/safe")
public class UnknownController {

    // SECRET UNKNOWN: only accessed in private method below, never from HTTP handler
    private static final String INTERNAL_KEY_UNKNOWN = "sk_live_javaUNK_xxxxxxxxxxx";

    /** Safe endpoint — called from HTTP. No vulnerabilities here. */
    @GetMapping("/version")
    public Map<String, String> version() {
        return Map.of("version", "1.0.0", "status", "ok");
    }

    /** CVE-2022-42889 UNKNOWN: commons-text StringSubstitutor with user input.
     *  Private method — never called from any HTTP handler. */
    private String expandVarsUnknown(String template) {
        return StringSubstitutor.replace(template, System.getenv());
    }

    /** CWE-326 UNKNOWN: weak 512-bit RSA key. Private, never on HTTP path. */
    private java.security.KeyPair generateWeakKeyUnknown() throws Exception {
        var kpg = java.security.KeyPairGenerator.getInstance("RSA");
        kpg.initialize(512); // CWE-326: key size too small
        return kpg.generateKeyPair();
    }

    /** DLP UNKNOWN: SSN + DOB logged, but this is never called from HTTP. */
    private void exportPiiUnknown(String ssn, String dob) {
        System.out.println("ssn=" + ssn + " dob=" + dob); // DLP UNKNOWN
    }

    /** SECRET UNKNOWN: returns internal key — private method, no HTTP route. */
    private String getInternalKeyUnknown() { return INTERNAL_KEY_UNKNOWN; }

    /** AI UNKNOWN: user input to LLM — private, never called from HTTP handler. */
    private String callLlmUnknown(String userInput) throws Exception {
        var url = new java.net.URL("https://api.openai.com/v1/chat/completions");
        var conn = (java.net.HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        var body = "{\"model\":\"gpt-4\",\"messages\":[{\"role\":\"user\",\"content\":\""
                   + userInput + "\"}]}"; // LLM01 UNKNOWN: unsanitized input
        conn.getOutputStream().write(body.getBytes());
        return "done";
    }
}
