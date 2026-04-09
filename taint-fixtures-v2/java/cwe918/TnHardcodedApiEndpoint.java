// Fixture: CWE-918 SSRF - Java
// VERDICT: TRUE_NEGATIVE
// PATTERN: hardcoded_api_base_url
// SOURCE: none (literal)
// SINK: RestTemplate.getForObject
// TAINT_HOPS: 0
// NOTES: Base URL hardcoded, only path param from user - safe
import org.springframework.web.client.RestTemplate;

public class TnHardcodedApiEndpoint {
    private static final String API_BASE = "https://api.internal.com";
    private final RestTemplate restTemplate = new RestTemplate();

    public String getUserProfile(String userId) {
        // SAFE: base URL is hardcoded constant
        return restTemplate.getForObject(API_BASE + "/users/" + userId, String.class);
    }
}
