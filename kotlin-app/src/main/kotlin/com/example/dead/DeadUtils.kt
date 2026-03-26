package com.example.dead

/**
 * DeadUtils — NOT_REACHABLE (Type C).
 *
 * This class is in com.example.dead.  It has NO Spring annotations,
 * is never instantiated by the container, and no other class imports
 * or references it.
 *
 * CVE-2022-42889 (Text4Shell) — NOT_REACHABLE: class never instantiated.
 * CWE-89 (SQL injection) — NOT_REACHABLE: class never instantiated.
 * SECRET — NOT_REACHABLE: class never instantiated.
 */
import org.apache.commons.text.StringSubstitutor
import java.sql.DriverManager

object DeadUtils {

    // SECRET: Dead admin key (NOT_REACHABLE — class never instantiated)
    const val DEAD_ADMIN_KEY = "sk_dead_kotlin_Np7Wq2xK8m"

    /** CVE-2022-42889 — NOT_REACHABLE (Type C): class never instantiated. */
    fun deadTemplate(input: String): String {
        val sub = StringSubstitutor.createInterpolator()
        return sub.replace(input)  // CVE NOT_REACHABLE (Type C)
    }

    /** CWE-89 — NOT_REACHABLE (Type C): class never instantiated. */
    fun deadQuery(userInput: String) {
        val conn = DriverManager.getConnection("jdbc:sqlite::memory:")
        val stmt = conn.createStatement()
        // CWE-89: SQL injection — NOT_REACHABLE (Type C)
        stmt.executeQuery("SELECT * FROM users WHERE name = '$userInput'")
    }
}
