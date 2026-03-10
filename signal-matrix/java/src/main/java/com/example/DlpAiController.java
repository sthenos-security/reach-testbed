package com.example;

import org.springframework.web.bind.annotation.*;
import java.util.Map;
import java.util.logging.Logger;

/**
 * DLP REACHABLE: PII flows to log + external HTTP from live @PostMapping endpoints.
 * AI REACHABLE: user input sent to LLM API from live @PostMapping endpoint.
 */
@RestController
@RequestMapping("/api/data")
public class DlpAiController {

    private static final Logger log = Logger.getLogger(DlpAiController.class.getName());

    /** DLP REACHABLE: SSN + DOB logged at INFO level from HTTP handler. */
    @PostMapping("/patient")
    public Map<String, Object> registerPatient(@RequestBody Map<String, String> body) {
        String ssn = body.get("ssn");
        String dob = body.get("dob");
        // DLP REACHABLE: PII → java.util.logging (log sink)
        log.info("Registering patient ssn=" + ssn + " dob=" + dob);
        return Map.of("status", "registered");
    }

    /** DLP REACHABLE: credit card + email sent to external CRM from HTTP handler. */
    @PostMapping("/sync")
    public Map<String, Object> syncCrm(@RequestBody Map<String, String> body) throws Exception {
        String card  = body.get("credit_card");
        String email = body.get("email");
        // DLP REACHABLE: PII → external HTTP POST
        var url  = new java.net.URL("https://crm.example.com/contacts");
        var conn = (java.net.HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.getOutputStream().write(("card=" + card + "&email=" + email).getBytes());
        return Map.of("status", "synced");
    }

    /** AI REACHABLE: user prompt sent to OpenAI without sanitization. LLM01. */
    @PostMapping("/llm")
    public Map<String, Object> callLlm(@RequestBody Map<String, String> body) throws Exception {
        String userPrompt = body.get("prompt");
        // LLM01 REACHABLE: unsanitized user input to external LLM API
        var url  = new java.net.URL("https://api.openai.com/v1/chat/completions");
        var conn = (java.net.HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        String reqBody = "{\"model\":\"gpt-4\",\"messages\":[{\"role\":\"user\",\"content\":\""
                         + userPrompt + "\"}]}"; // VIOLATION: unsanitized
        conn.getOutputStream().write(reqBody.getBytes());
        return Map.of("status", "sent");
    }

    /** AI REACHABLE: eval(LLM output). LLM05. */
    @PostMapping("/execute")
    public Map<String, Object> executeLlmOutput(@RequestBody Map<String, String> body)
            throws Exception {
        String llmCode = body.get("code");
        // LLM05 REACHABLE: executing LLM output via ScriptEngine (eval equivalent)
        var engine = new javax.script.ScriptEngineManager().getEngineByName("js");
        engine.eval(llmCode); // VIOLATION: executing untrusted LLM output
        return Map.of("executed", true);
    }
}
