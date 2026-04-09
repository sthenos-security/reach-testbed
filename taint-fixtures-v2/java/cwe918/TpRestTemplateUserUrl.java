// Fixture: CWE-918 SSRF - Java
// VERDICT: TRUE_POSITIVE
// PATTERN: resttemplate_user_controlled_url
// SOURCE: request parameter
// SINK: RestTemplate.getForObject
// TAINT_HOPS: 1
// NOTES: Spring RestTemplate with user-controlled URL
// REAL_WORLD: Common in Spring webhook/proxy endpoints
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

@RestController
public class TpRestTemplateUserUrl {
    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/proxy")
    public String proxy(@RequestParam String targetUrl) {
        // VULNERABLE: user controls the URL
        return restTemplate.getForObject(targetUrl, String.class);
    }
}
