plugins {
    id("org.jetbrains.kotlin.jvm") version "1.9.0"
    id("application")
}

group = "com.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    // CVE Test Cases:
    // spring-boot 2.7.5  → CVE-2022-22965 (Spring4Shell RCE if JDK 9+)
    //                       CVE-2022-22950 (DoS via SpEL)
    // log4j 2.17.1       → CVE-2021-44832 (RCE via JDBC Appender) 
    // jackson-databind 2.13.2 → CVE-2022-42003 (deep recursion DoS)
    //                           CVE-2022-42004 (deep recursion DoS)
    // netty 4.1.76.Final → CVE-2022-24823 (temp file info disclosure)
    // commons-text 1.9   → CVE-2022-42889 (Text4Shell — ${script:...} RCE)

    implementation("org.springframework.boot:spring-boot-starter-web:2.7.5")
    implementation("org.springframework.boot:spring-boot-starter-security:2.7.5")
    implementation("org.apache.logging.log4j:log4j-core:2.17.1")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.13.2")
    implementation("io.netty:netty-all:4.1.76.Final")
    implementation("org.apache.commons:commons-text:1.9")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.6.4")
    
    testImplementation(kotlin("test"))
    testImplementation("org.springframework.boot:spring-boot-starter-test:2.7.5")
}

application {
    mainClass.set("com.example.ApplicationKt")
}

kotlin {
    jvmToolchain(17)
}
