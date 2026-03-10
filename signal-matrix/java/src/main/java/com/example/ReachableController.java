package com.example;

import org.springframework.web.bind.annotation.*;
import org.yaml.snakeyaml.Yaml;
import java.util.Map;

/**
 * CVE REACHABLE: SnakeYAML CVE-2022-1471 — live @PostMapping endpoint.
 * CWE REACHABLE: SQL injection + path traversal in live handlers.
 * SECRET REACHABLE: hardcoded DB password used in live handler.
 */
@RestController
@RequestMapping("/api")
public class ReachableController {

    // SECRET REACHABLE: hardcoded credential used in handler below
    private static final String DB_PASSWORD    = "db_javaREACH_secret_99999";
    private static final String PAYMENT_TOKEN  = "sk_live_javaREACH_xxxxxxxxxxx";

    /** CVE-2022-1471 REACHABLE: unsafe YAML deserialization from user input. */
    @PostMapping("/config")
    public Map<String, Object> parseConfig(@RequestBody String yamlContent) {
        Yaml yaml = new Yaml(); // CVE-2022-1471: no SafeConstructor
        Object config = yaml.load(yamlContent); // REACHABLE trigger
        return Map.of("parsed", config);
    }

    /** CWE-89 REACHABLE: SQL injection via string concatenation. */
    @PostMapping("/query")
    public Map<String, Object> query(@RequestBody Map<String, String> body) throws Exception {
        String name = body.get("name");
        var conn = java.sql.DriverManager.getConnection(
            "jdbc:h2:mem:test", "sa", DB_PASSWORD); // SECRET REACHABLE
        // CWE-89 REACHABLE: string concat in SQL
        var rs = conn.createStatement().executeQuery(
            "SELECT * FROM users WHERE name='" + name + "'");
        return Map.of("found", rs.next());
    }

    /** CWE-22 REACHABLE: path traversal via unsanitized filename. */
    @GetMapping("/file")
    public Map<String, Object> readFile(@RequestParam String name) throws Exception {
        // CWE-22 REACHABLE: no path sanitization
        var path = java.nio.file.Paths.get("/var/data", name);
        var content = java.nio.file.Files.readString(path);
        return Map.of("content", content);
    }

    /** CWE-611 REACHABLE: XXE via unsecured XML parser. */
    @PostMapping("/xml")
    public Map<String, Object> parseXml(@RequestBody String xmlContent) throws Exception {
        var factory = javax.xml.parsers.DocumentBuilderFactory.newInstance();
        // CWE-611 REACHABLE: external entities not disabled
        var builder = factory.newDocumentBuilder();
        var doc = builder.parse(new java.io.ByteArrayInputStream(xmlContent.getBytes()));
        return Map.of("root", doc.getDocumentElement().getNodeName());
    }

    /** SECRET REACHABLE: payment token in response. */
    @GetMapping("/pay")
    public Map<String, Object> getPaymentConfig() {
        return Map.of("token", PAYMENT_TOKEN.substring(0, 4) + "****");
    }
}
