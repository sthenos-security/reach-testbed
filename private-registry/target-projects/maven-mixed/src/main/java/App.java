package com.test;

import org.apache.commons.lang3.StringUtils;

/**
 * Maven mixed registry demo app.
 * Uses commons-lang3 (public) and H2 (CVE target: 1.4.197 has critical RCE).
 */
public class App {

    public static void main(String[] args) {
        System.out.println("App started");
        System.out.println("Blank check: " + StringUtils.isBlank(""));

        try {
            Class.forName("org.h2.Driver");
            var conn = java.sql.DriverManager.getConnection("jdbc:h2:mem:test");
            var stmt = conn.createStatement();
            stmt.execute("CREATE TABLE demo (id INT PRIMARY KEY, name VARCHAR(255))");
            stmt.execute("INSERT INTO demo VALUES (1, 'test')");
            var rs = stmt.executeQuery("SELECT * FROM demo");
            while (rs.next()) {
                System.out.println("Row: " + rs.getInt("id") + " = " + rs.getString("name"));
            }
            conn.close();
        } catch (Exception e) {
            System.err.println("H2 error: " + e.getMessage());
        }
    }
}
