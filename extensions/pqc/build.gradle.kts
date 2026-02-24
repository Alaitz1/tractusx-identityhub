plugins {
    id("java")
}

group = "org.eclipse.tractusx.ih"
version = "0.1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.10.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    implementation(libs.edc.ih.spi)
    implementation("org.eclipse.edc:keypair-spi:0.14.0")
    implementation(libs.edc.spi.transaction)
    implementation(libs.edc.lib.keys)
    implementation(libs.edc.lib.crypto)
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.79")
    testImplementation(libs.edc.junit)

}

tasks.test {
    useJUnitPlatform()
}