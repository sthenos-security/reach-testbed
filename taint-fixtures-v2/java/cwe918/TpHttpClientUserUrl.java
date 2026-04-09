// Fixture: CWE-918 SSRF - Java
// VERDICT: TRUE_POSITIVE
// PATTERN: httpclient_user_controlled_url
// SOURCE: function_parameter
// SINK: HttpClient.send
// TAINT_HOPS: 1
// NOTES: Java 11+ HttpClient with user-controlled URL
import java.net.URI;
import java.net.http.*;

public class TpHttpClientUserUrl {
    public String fetchUrl(String url) throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .build();
        // VULNERABLE: user controls URL
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        return response.body();
    }
}
