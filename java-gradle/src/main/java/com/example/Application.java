package com.example;

import org.apache.commons.text.StringSubstitutor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.sql.Connection;
import java.sql.DriverManager;
import java.util.Map;

/**
 * Java Test App — REACHABLE testbed (Maven variant)
 *
 * REACHABLE CVEs:
 *   CVE-2022-42889 (Text4Shell) — /api/template handler uses StringSubstitutor
 *   CVE-2022-42003 (Jackson DoS) — /api/parse handler uses ObjectMapper
 *   CVE-2022-45868 (H2 RCE) — /api/db handler uses H2 with INIT URL param
 *   CVE-2022-22965 (Spring4Shell) — Spring MVC class binding is implicit
 *
 * NOT_REACHABLE:
 *   deadLog4jRce() — never called from any HTTP handler
 */
@SpringBootApplication
@RestController
@RequestMapping("/api")
public class Application {

    private static final Logger log = LogManager.getLogger(Application.class);

    // HARDCODED SECRETS (SECRET signal)
    private static final String DB_PASSWORD = "super_secret_db_pass_abc123";
    private static final String API_KEY = "AKIAIOSFODNN7JAVATEST";
    private static final String STRIPE_KEY = "sk_live_java_test_fakekeyfortest12345678";

    private final ObjectMapper objectMapper = new ObjectMapper();

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    /**
     * REACHABLE: CVE-2022-42889 (Text4Shell)
     * StringSubstitutor.createInterpolator().replace(userInput) enables:
     *   ${script:javascript:java.lang.Runtime.getRuntime().exec('id')}
     */
    @GetMapping("/template")
    public Map<String, String> template(@RequestParam String tmpl) {
        StringSubstitutor sub = StringSubstitutor.createInterpolator();
        sub.setEnableSubstitutionInVariables(true);
        String result = sub.replace(tmpl);  // CVE-2022-42889
        return Map.of("result", result, "key", API_KEY);  // Also leaks key
    }

    /**
     * REACHABLE: CVE-2022-42003/42004 (Jackson deep recursion DoS)
     */
    @PostMapping("/parse")
    public Map<String, Object> parse(@RequestBody String json) throws Exception {
        Map<?, ?> parsed = objectMapper.readValue(json, Map.class);  // CVE-2022-42003
        return Map.of("keys", parsed.size());
    }

    /**
     * REACHABLE: CVE-2022-45868 (H2 database RCE via INIT script in URL)
     * Attacker controls dbUrl parameter to inject INIT=runscript from
     */
    @GetMapping("/db")
    public Map<String, String> dbConnect(@RequestParam String dbUrl) {
        try {
            // VULNERABLE: user-controlled JDBC URL with H2
            Connection conn = DriverManager.getConnection(dbUrl, "sa", DB_PASSWORD);
            conn.close();
            return Map.of("status", "connected");
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    /** SAFE: health check */
    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "ok");
    }

    /**
     * NOT_REACHABLE: dead code — never called from any route handler
     * log4j CVE-2021-44832: JDBC Appender with attacker-controlled URL
     */
    private void deadLog4jRce(String logInput) {
        // Would trigger CVE-2021-44832 with a crafted log4j2.xml JDBC URL
        log.error("dead: {}", logInput);
    }
}
