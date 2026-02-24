import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.eclipse.tractusx.identityhub.pqc.PqcKeyPairFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.Security;

import static org.assertj.core.api.Assertions.assertThat;



class PqcKeyPairFactoryTest {

    @BeforeAll
    static void setupProvider() {
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    @Test
    void shouldGenerateDefaultSsiHybridKeys() throws Exception {
        var result = PqcKeyPairFactory.generateDefaultSsiHybrid();

        assertThat(result).isNotNull();
        assertThat(result.getClassicalKeyPair()).isNotNull();
        assertThat(result.getPqcKeyPair()).isNotNull();

        assertThat(result.getClassicalKeyPair().getPublic().getAlgorithm()).containsAnyOf("EdDSA", "Ed25519");
        assertThat(result.getPqcKeyPair().getPublic().getAlgorithm()).containsIgnoringCase("DILITHIUM");
    }

    @Test
    void shouldGenerateCustomHybridKeys() throws Exception {

        var result = PqcKeyPairFactory.generate("EC", "secp256r1", "Falcon", "falcon-512");

        // Assert
        assertThat(result).isNotNull();
        assertThat(result.getClassicalKeyPair()).isNotNull();
        assertThat(result.getPqcKeyPair()).isNotNull();

        assertThat(result.getClassicalKeyPair().getPublic().getAlgorithm()).isEqualTo("EC");
        assertThat(result.getPqcKeyPair().getPublic().getAlgorithm()).containsIgnoringCase("FALCON");
    }
}