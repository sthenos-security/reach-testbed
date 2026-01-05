package com.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Map;

/**
 * Java Test App - Known Vulnerabilities
 * 
 * REACHABLE CVEs:
 * - CVE-2022-22965 (Spring4Shell) - triggered via data binding
 * - CVE-2022-1471 (SnakeYAML) - triggered via /api/config
 * 
 * UNREACHABLE CVEs:
 * - CVE-2021-42392 (H2 Console) - test scope only
 */
@SpringBootApplication
@RestController
public class Application {

    // ========================================================================
    // REACHABLE SECRET - Hardcoded credentials
    // ========================================================================
    private static final String DB_PASSWORD = "super_secret_password_123";
    private static final String API_KEY = "sk-proj-xxxxxxxxxxxxxxxxxxxx";

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    // ========================================================================
    // REACHABLE CVE: Spring4Shell (CVE-2022-22965)
    // Data binding on class objects can lead to RCE
    // ========================================================================
    @PostMapping("/api/user")
    public Map<String, Object> createUser(@ModelAttribute UserForm form) {
        // CVE-2022-22965: Spring data binding vulnerability
        // Attacker can manipulate class.module.classLoader...
        return Map.of(
            "name", form.getName(),
            "email", form.getEmail(),
            "created", true
        );
    }

    // ========================================================================
    // REACHABLE CVE: SnakeYAML (CVE-2022-1471)
    // Unsafe YAML deserialization
    // ========================================================================
    @PostMapping("/api/config")
    public Map<String, Object> parseConfig(@RequestBody String yamlContent) {
        // CVE-2022-1471: Arbitrary code execution via YAML deserialization
        Yaml yaml = new Yaml();  // Unsafe - no SafeConstructor
        Object config = yaml.load(yamlContent);
        return Map.of("config", config, "parsed", true);
    }

    // ========================================================================
    // REACHABLE SECRET: Database connection using hardcoded password
    // ========================================================================
    @GetMapping("/api/db-status")
    public Map<String, Object> dbStatus() {
        // Using hardcoded credential
        String connectionString = "jdbc:postgresql://localhost:5432/mydb?password=" + DB_PASSWORD;
        return Map.of(
            "status", "connected",
            "connection", connectionString.substring(0, 50) + "..."
        );
    }

    // ========================================================================
    // SAFE ENDPOINT - No vulnerabilities
    // ========================================================================
    @GetMapping("/api/health")
    public Map<String, Object> health() {
        return Map.of("status", "ok", "version", "1.0.0");
    }

    // ========================================================================
    // UNREACHABLE CODE - Never called
    // ========================================================================
    private void unusedMethod() {
        // This method is never called from any entrypoint
        // H2 CVE would only be relevant if this was reached
        String h2Url = "jdbc:h2:mem:testdb";
        // H2 database usage would go here
    }

    // ========================================================================
    // FORM CLASS for Spring data binding
    // ========================================================================
    public static class UserForm {
        private String name;
        private String email;

        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
    }
}
