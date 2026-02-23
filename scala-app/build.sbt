name := "reach-testbed-scala"
version := "0.1.0"
scalaVersion := "2.13.12"

// CVE Test Cases for REACHABLE Scala dep scanning (SBT/Grype):
//
// jackson-databind 2.13.0 → CVE-2022-42003 (deep wrapper array nesting DoS)
//                           CVE-2022-42004 (deep merge DoS)
// logback-classic 1.2.3  → CVE-2021-42550 (JNDI injection via JNDI lookup in config)
//                           CVE-2023-6378 (serialization vulnerability)
// commons-text 1.9       → CVE-2022-42889 (Text4Shell — StringSubstitutor RCE)
// play-json 2.9.3        → No known CVE — baseline SBOM coverage
// akka-http 10.2.9       → CVE-2022-23340 (HTTP request smuggling)

libraryDependencies ++= Seq(
  // Jackson — serialization (multiple CVEs)
  "com.fasterxml.jackson.core"   % "jackson-databind"    % "2.13.0",
  "com.fasterxml.jackson.module" %% "jackson-module-scala" % "2.13.0",

  // Logback — logging (CVE-2021-42550, CVE-2023-6378)
  "ch.qos.logback" % "logback-classic" % "1.2.3",

  // Apache Commons Text — Text4Shell (CVE-2022-42889)
  "org.apache.commons" % "commons-text" % "1.9",

  // Play JSON — baseline
  "com.typesafe.play" %% "play-json" % "2.9.3",

  // Akka HTTP — HTTP request smuggling (CVE-2022-23340)
  "com.typesafe.akka" %% "akka-http"       % "10.2.9",
  "com.typesafe.akka" %% "akka-stream"     % "2.6.20",
  "com.typesafe.akka" %% "akka-actor-typed" % "2.6.20",
)
