// Fixture: CWE-79 Cross-Site Scripting - Java
// VERDICT: TRUE_NEGATIVE
// PATTERN: spring_thymeleaf_escaped
// SOURCE: request parameter
// SINK: Model attribute (Thymeleaf rendered)
// TAINT_HOPS: 1
// NOTES: Thymeleaf th:text auto-escapes by default - safe
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
public class TnJspElAutoEscape {
    @GetMapping("/profile")
    public String profile(@RequestParam String name, Model model) {
        // SAFE: Thymeleaf th:text auto-escapes; only th:utext is unsafe
        model.addAttribute("name", name);
        return "profile";
    }
}
