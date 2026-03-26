package com.example

/**
 * AdminService — NOT_REACHABLE (Type A).
 *
 * This class has @Service annotation, so Spring will instantiate it.
 * However, no @Controller or other bean injects it via constructor
 * or @Autowired, so its methods are never called from HTTP endpoints.
 *
 * CWE-78 (command injection) — NOT_REACHABLE: service never injected.
 * SECRET — NOT_REACHABLE: key defined but inaccessible.
 */
import org.springframework.stereotype.Service

@Service
class AdminService {

    // SECRET: Hardcoded admin token (NOT_REACHABLE — service never injected)
    private val adminToken = "adm_live_kotlin_8kZp3Q"

    /** CWE-78 — NOT_REACHABLE (Type A): @Service exists but no controller injects it. */
    fun executeCommand(cmd: String): String {
        // CWE-78: command injection — NOT_REACHABLE (Type A)
        val process = Runtime.getRuntime().exec(arrayOf("sh", "-c", cmd))
        return process.inputStream.bufferedReader().readText()
    }

    /** SECRET — NOT_REACHABLE (Type A). */
    fun getAdminToken(): String = adminToken  // SECRET NOT_REACHABLE (Type A)
}
