plugins {
    id("com.android.library") version "8.2.0"
    id("org.jetbrains.kotlin.android") version "1.9.22"
    `maven-publish`
    signing
}

val libVersion: String = project.findProperty("version") as? String ?: "0.1.0"

android {
    namespace = "org.spacesprotocol.libveritas"
    compileSdk = 34

    defaultConfig {
        minSdk = 24

    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    kotlinOptions {
        jvmTarget = "1.8"
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

dependencies {
    implementation("net.java.dev.jna:jna:5.14.0@aar")
}

publishing {
    publications {
        register<MavenPublication>("release") {
            groupId = "org.spacesprotocol"
            artifactId = "libveritas"
            version = libVersion

            afterEvaluate {
                from(components["release"])
            }

            pom {
                name.set("libveritas")
                description.set("Veritas verification library for Android")
                url.set("https://github.com/spacesprotocol/libveritas")

                licenses {
                    license {
                        name.set("MIT")
                        url.set("https://github.com/spacesprotocol/libveritas/blob/main/LICENSE")
                    }
                }

                developers {
                    developer {
                        id.set("spacesprotocol")
                        name.set("spacesprotocol")
                    }
                }

                scm {
                    connection.set("scm:git:git://github.com/spacesprotocol/libveritas.git")
                    developerConnection.set("scm:git:ssh://github.com/spacesprotocol/libveritas.git")
                    url.set("https://github.com/spacesprotocol/libveritas")
                }
            }
        }
    }

    repositories {
        maven {
            name = "OSSRH"
            url = uri("https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/")
            credentials {
                username = System.getenv("OSSRH_USERNAME")
                password = System.getenv("OSSRH_PASSWORD")
            }
        }
    }
}

signing {
    val signingKey = System.getenv("GPG_SIGNING_KEY")
    val signingPassword = System.getenv("GPG_PASSPHRASE")
    if (signingKey != null && signingPassword != null) {
        useInMemoryPgpKeys(signingKey, signingPassword)
        sign(publishing.publications["release"])
    }
}
