// Fixture: code_patch · CWE-89 SQL Injection · Java
// VERDICT: TRUE_NEGATIVE
// PATTERN: jpa_named_parameter
// SOURCE: http_request (request.getParameter)
// SINK: EntityManager.createQuery (named param)
// TAINT_HOPS: 1
// NOTES: JPA named parameters — properly bound
import javax.servlet.http.*;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.io.*;

public class TnJpaNamedParam extends HttpServlet {
    @PersistenceContext
    private EntityManager em;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String name = request.getParameter("name");
        // SAFE: JPA query with named parameter binding
        em.createQuery("SELECT u FROM User u WHERE u.name = :name")
          .setParameter("name", name)
          .getResultList();
    }
}
