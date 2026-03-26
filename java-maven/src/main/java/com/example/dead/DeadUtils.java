package com.example.dead;

/**
 * DeadUtils — NOT_REACHABLE (Type C).
 *
 * This class is in the com.example.dead package.  Although Spring's
 * component scan covers com.example.*, this class has NO @Service,
 * @Component, or any Spring annotation, so Spring never instantiates
 * it.  No other class imports or references it.
 *
 * CVE-2022-1471 (SnakeYAML) — NOT_REACHABLE: class never instantiated.
 * CWE-89 (SQL injection) — NOT_REACHABLE: class never instantiated.
 * SECRET — NOT_REACHABLE: class never instantiated.
 */
import org.yaml.snakeyaml.Yaml;
import java.sql.*;

public class DeadUtils {

    // SECRET: Dead admin key (NOT_REACHABLE — class never instantiated)
    private static final String DEAD_ADMIN_KEY = "sk_dead_spring_Np7Wq2xK8m";

    /**
     * CVE-2022-1471 — NOT_REACHABLE (Type C): class never instantiated.
     */
    public static Object parseYaml(String input) {
        Yaml yaml = new Yaml();
        return yaml.load(input);  // CVE NOT_REACHABLE (Type C)
    }

    /**
     * CWE-89 — NOT_REACHABLE (Type C): class never instantiated.
     */
    public static ResultSet deadQuery(String userInput) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:sqlite::memory:");
        Statement stmt = conn.createStatement();
        // CWE-89: SQL injection — NOT_REACHABLE (Type C)
        return stmt.executeQuery("SELECT * FROM users WHERE name = '" + userInput + "'");
    }
}
