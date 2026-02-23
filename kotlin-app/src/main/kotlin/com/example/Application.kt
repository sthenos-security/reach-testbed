package com.example

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.web.bind.annotation.*
import org.apache.commons.text.StringSubstitutor
import com.fasterxml.jackson.databind.ObjectMapper
import org.apache.logging.log4j.LogManager

/**
 * Kotlin Test App — REACHABLE testbed
 *
 * REACHABLE CVEs:
 *   CVE-2022-42889 (Text4Shell) — StringSubstitutor called from /api/template
 *   CVE-2022-42003 (Jackson DoS) — ObjectMapper called from /api/parse
 *   CVE-2022-22965 (Spring4Shell) — Spring MVC binding (Spring itself)
 *
 * NOT_REACHABLE:
 *   deadLog4jExec() — never called from any controller
 */
@SpringBootApplication
class Application

fun main(args: Array<String>) {
    runApplication<Application>(*args)
}

@RestController
@RequestMapping("/api")
class SecurityTestController {

    private val objectMapper = ObjectMapper()
    // HARDCODED SECRET (SECRET signal)
    private val apiKey = "sk-kotlin-test-AKIAIOSFODNN7KTEXAMPLE"
    
    /**
     * REACHABLE: CVE-2022-42889 (Text4Shell)
     * StringSubstitutor.replace() with user input enables script injection:
     * ${script:javascript:java.lang.Runtime.getRuntime().exec('calc')}
     */
    @GetMapping("/template")
    fun renderTemplate(@RequestParam template: String): Map<String, String> {
        // VULNERABLE: passes user input directly to StringSubstitutor
        val substitutor = StringSubstitutor.createInterpolator()
        substitutor.isEnableSubstitutionInVariables = true
        val result = substitutor.replace(template)   // CVE-2022-42889 trigger
        return mapOf("result" to result)
    }

    /**
     * REACHABLE: CVE-2022-42003 / CVE-2022-42004 (Jackson deep recursion DoS)
     * readValue on attacker-controlled JSON with nested arrays causes stack overflow
     */
    @PostMapping("/parse")
    fun parseJson(@RequestBody json: String): Map<String, Any> {
        val parsed = objectMapper.readValue(json, Map::class.java)  // CVE-2022-42003
        return mapOf("keys" to parsed.keys.size, "source" to "jackson")
    }

    /**
     * SAFE: health check — no CVE trigger
     */
    @GetMapping("/health")
    fun health(): Map<String, String> = mapOf("status" to "ok")

    /**
     * NOT_REACHABLE: dead code block — never called from any handler
     * log4j CVE-2021-44832: attacker-controlled JDBC URL in log4j config
     */
    @Suppress("unused")
    fun deadLog4jExec(input: String) {
        val logger = LogManager.getLogger("dead")
        // Would trigger CVE-2021-44832 but this function is never called
        logger.error("Dead: {}", input)
    }
}
