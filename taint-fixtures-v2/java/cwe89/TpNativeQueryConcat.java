// Fixture: code_patch · CWE-89 SQL Injection · Java
// VERDICT: TRUE_POSITIVE
// PATTERN: jpa_native_query_concat
// SOURCE: http_request (request.getParameter)
// SINK: EntityManager.createNativeQuery (string concat)
// TAINT_HOPS: 1
import javax.servlet.http.*;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.io.*;

public class TpNativeQueryConcat extends HttpServlet {
    @PersistenceContext
    private EntityManager em;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String name = request.getParameter("name");
        // VULNERABLE: CWE-89 · JPA native query with string concatenation
        em.createNativeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }
}
