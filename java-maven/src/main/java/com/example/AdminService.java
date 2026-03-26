package com.example;

/**
 * AdminService — NOT_REACHABLE (Type A).
 *
 * This class has @Service annotation, so Spring will instantiate it
 * during component scan.  However, no @Controller or other bean
 * injects it via @Autowired, so its methods are never called from
 * any HTTP endpoint.
 *
 * CWE-78 (command injection) — NOT_REACHABLE: service never injected.
 * SECRET — NOT_REACHABLE: key defined but inaccessible.
 */
import org.springframework.stereotype.Service;
import java.io.IOException;

@Service
public class AdminService {

    // SECRET: Hardcoded admin token (NOT_REACHABLE — service never injected)
    private static final String ADMIN_TOKEN = "adm_live_spring_7mXq2K";

    /**
     * CWE-78 — NOT_REACHABLE (Type A): @Service exists but no controller
     * injects AdminService.
     */
    public String executeCommand(String cmd) throws IOException {
        // CWE-78: command injection — NOT_REACHABLE (Type A)
        Process p = Runtime.getRuntime().exec(cmd);
        return new String(p.getInputStream().readAllBytes());
    }

    /**
     * SECRET — NOT_REACHABLE (Type A): endpoint inaccessible.
     */
    public String getAdminToken() {
        return ADMIN_TOKEN;  // SECRET NOT_REACHABLE (Type A)
    }
}
