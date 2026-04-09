// Fixture: CWE-79 Cross-Site Scripting - Java
// VERDICT: TRUE_POSITIVE
// PATTERN: spring_response_body_html_concat
// SOURCE: request parameter
// SINK: ResponseEntity
// TAINT_HOPS: 1
// NOTES: Spring MVC returning HTML with user input via @ResponseBody
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

@RestController
public class TpSpringModelAttribute {
    @GetMapping("/search")
    public ResponseEntity<String> search(@RequestParam String query) {
        // VULNERABLE: user input reflected in HTML response
        String html = "<html><body>Results for: " + query + "</body></html>";
        return ResponseEntity.ok().header("Content-Type", "text/html").body(html);
    }
}
