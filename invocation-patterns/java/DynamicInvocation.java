// Copyright © 2026 Sthenos Security. All rights reserved.
// ============================================================================
// INVOCATION PATTERNS TEST — Case 4: Dynamic Invocation (Java)
//
// Tests patterns where static call graph misses function reachability because
// the method is invoked via reflection, functional interfaces, lambdas,
// or runtime-resolved class loading.
//
// Each case is annotated with:
//   REACH: expected reachability state
//   CG:    whether static CG catches it (YES / NO / PARTIAL)
//   WHY:   root cause if static CG misses
// ============================================================================
package com.example;

import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Component;

import java.io.*;
import java.lang.reflect.*;
import java.nio.file.*;
import java.sql.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.*;


@RestController
@RequestMapping("/dynamic")
public class DynamicInvocation {

    // ── CASE 1: Functional interface (Function<T,R>) ───────────────────────
    // REACH: REACHABLE   CG: YES (after fix)   CONFIDENCE: HIGH
    // Lambda assigned to Function variable and called from HTTP handler.

    private final Function<String, String> buildQuery = name -> {
        // CWE-89: SQL injection via functional interface lambda
        return "SELECT * FROM users WHERE name='" + name + "'"; // CWE-89 REACHABLE
    };

    @GetMapping("/functional")
    public Map<String, String> functionalDispatch(@RequestParam String name) {
        String query = buildQuery.apply(name); // CG should trace lambda as reachable
        return Map.of("query", query);
    }


    // ── CASE 2: Method reference ───────────────────────────────────────────
    // REACH: REACHABLE   CG: YES (after fix)   CONFIDENCE: HIGH
    // ClassName::methodName stored in a Function variable.

    private static String buildDeleteQuery(String id) {
        // CWE-89: SQL injection via method reference
        return "DELETE FROM sessions WHERE id=" + id; // CWE-89 REACHABLE
    }

    @PostMapping("/method-ref")
    public Map<String, String> methodRef(@RequestBody Map<String, String> body) {
        Function<String, String> fn = DynamicInvocation::buildDeleteQuery;
        String query = fn.apply(body.get("id")); // CG: trace method ref → buildDeleteQuery
        return Map.of("query", query);
    }


    // ── CASE 3: Reflection — Method.invoke() ──────────────────────────────
    // REACH: UNKNOWN   CG: NO   CONFIDENCE: LOW
    // Method name resolved from user input at runtime — CG cannot determine callee.

    private void secretDump(String path) throws IOException {
        // CWE-22: path traversal. Called via Method.invoke() if methodName == "secretDump".
        String content = new String(Files.readAllBytes(Paths.get(path))); // CWE-22 UNKNOWN
        System.out.println(content);
    }

    @GetMapping("/reflect")
    public Map<String, Object> reflectInvoke(
            @RequestParam String methodName,
            @RequestParam String arg) {
        try {
            // CWE-22 UNKNOWN: method resolved from user-supplied string
            Method m = this.getClass().getDeclaredMethod(methodName, String.class);
            m.setAccessible(true);
            m.invoke(this, arg); // CG: NO — method name is runtime string
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
        return Map.of("status", "invoked");
    }


    // ── CASE 4: Class.forName() + newInstance() ────────────────────────────
    // REACH: UNKNOWN   CG: NO   CONFIDENCE: LOW
    // Class name determined at runtime — CG cannot analyze the instantiated class.

    interface Processor {
        String process(String input);
    }

    @GetMapping("/class-forname")
    public Map<String, Object> classForName(@RequestParam String className,
                                             @RequestParam String input) {
        try {
            // CWE-829: Uncontrolled class loading
            Class<?> cls = Class.forName(className); // CWE-829 UNKNOWN
            Processor p = (Processor) cls.getDeclaredConstructor().newInstance();
            return Map.of("result", p.process(input));
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }


    // ── CASE 5: Executor submit with Callable / Runnable ──────────────────
    // REACH: REACHABLE   CG: YES (after fix)   CONFIDENCE: HIGH
    // Lambda submitted to executor — CG should trace lambda body as reachable.

    private final ExecutorService executor = Executors.newFixedThreadPool(2);

    private String runShellCommand(String cmd) throws Exception {
        // CWE-78: OS command via executor-submitted task
        Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd}); // CWE-78 REACHABLE
        return new String(p.getInputStream().readAllBytes());
    }

    @PostMapping("/executor")
    public Map<String, Object> executorSubmit(@RequestBody Map<String, String> body) {
        String cmd = body.getOrDefault("cmd", "echo ok");
        Future<String> future = executor.submit(() -> runShellCommand(cmd));
        try {
            return Map.of("result", future.get());
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }


    // ── CASE 6: Map of Runnables / Suppliers ──────────────────────────────
    // REACH: REACHABLE   CG: PARTIAL   CONFIDENCE: MEDIUM
    // CG should see map literal values; which one runs is PARTIAL.

    private String sqlAction(String input) {
        // CWE-89: SQL injection via map-dispatched supplier
        return "INSERT INTO logs (msg) VALUES ('" + input + "')"; // CWE-89 REACHABLE
    }

    private String cmdAction(String input) {
        // CWE-78: OS command via map-dispatched supplier
        try {
            return new String(Runtime.getRuntime()
                .exec(new String[]{"sh", "-c", "echo " + input})
                .getInputStream().readAllBytes()); // CWE-78 REACHABLE
        } catch (IOException e) { return ""; }
    }

    @PostMapping("/map-dispatch")
    public Map<String, Object> mapDispatch(@RequestBody Map<String, String> body) {
        Map<String, Function<String, String>> handlers = Map.of(
            "sql", this::sqlAction,
            "cmd", this::cmdAction
        );
        String action = body.get("action");
        String input  = body.get("input");
        Function<String, String> fn = handlers.get(action);
        if (fn != null) {
            return Map.of("result", fn.apply(input)); // CG: PARTIAL
        }
        return Map.of("error", "unknown action");
    }


    // ── CASE 7: Dead code — never referenced by any handler ───────────────
    // REACH: NOT_REACHABLE   CG: YES

    private void deadDynamicHandler(String input) throws Exception {
        // CWE-78: never passed to any executor, map, or reflection call
        Runtime.getRuntime().exec(new String[]{"sh", "-c", "rm -rf " + input}); // CWE-78 NOT_REACHABLE
    }
}
