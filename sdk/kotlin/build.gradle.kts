plugins {
    kotlin("jvm") version "2.4.20"
    kotlin("plugin.serialization") version "2.4.20"
    // Ohne dieses Plugin existiert `publishToMavenLocal` nicht und das
    // Kotlin-SDK waere als einziges der drei Clients nicht auslieferbar. Der
    // Release-Trockenlauf in der CI prueft das ab sofort automatisch, statt wie
    // bisher das Fehlen des Plugins zu melden.
    `maven-publish`
}

group = "de.eudi.verify"
version = "0.1.0"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.11.0")
    testImplementation(kotlin("test"))
}

publishing {
    publications {
        // "maven" ist der artefaktuebergreifende Name, den der CI-Schritt
        // `publishToMavenLocal` ohne Argument aufruft. Er darf deshalb nicht
        // umbenannt werden, sonst findet der Job das Ziel nicht mehr.
        create<MavenPublication>("maven") {
            // Nur die Hauptquelle. Die Tests gehoeren nicht in die
            // Veroeffentlichung; das haelt dasselbe Prinzip wie bei den beiden
            // anderen Clients, wo der Release-Trockenlauf die Archive prueft.
            from(components["java"])
            artifactId = "eudi-verify-sdk-kotlin"
            pom {
                name.set("EUDI Verify Kotlin SDK")
                description.set("Typed JVM client for the Attack EUDI Verifier API")
            }
        }
    }
}

kotlin {
    // Der Client ist eine Bibliothek und laeuft auf der JVM-Zielversion der
    // genutzten Laufzeitumgebung, nicht auf der des Builders.
    explicitApi()
    compilerOptions {
        allWarningsAsErrors.set(true)
    }
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
}

/**
 * Rauchtest gegen einen laufenden Dienst, getrennt von `gradle test`:
 * er braucht Netz und einen laufenden Attack-Dienst.
 */
tasks.register<JavaExec>("runSmoke") {
    group = "verification"
    description = "Ruft die Betriebs- und Mandantenrouten eines laufenden Dienstes ab"
    mainClass.set("de.eudi.verify.sdk.LiveSmoke")
    classpath = sourceSets.main.get().runtimeClasspath
}
