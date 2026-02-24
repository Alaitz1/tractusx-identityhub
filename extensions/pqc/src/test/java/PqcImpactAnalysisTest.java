import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.eclipse.tractusx.identityhub.pqc.KeyPairGenerator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

@DisplayName("Comprehensive Comparative Study: NIST PQC Variants")
class PqcImpactAnalysisTest {

    @BeforeAll
    static void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());

        System.out.println("| Family | Variant | PubKey (B) | PrivKey (B) | Signature (B) | Est. JWT (B) | Header Safe? |");
        System.out.println("| :--- | :--- | :---: | :---: | :---: | :---: | :---: |");
    }

    // Actualizado para recibir algorithm y parameterSpec por separado
    @ParameterizedTest(name = "Analysis: {0} - {1} {2}")
    @MethodSource("provideAllVariants")
    @DisplayName("Impact Study: Cryptographic Material Sizes and Transport Viability")
    void analyzeVariantImpact(String family, String algorithm, String parameterSpec) throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("algorithm", algorithm);
        if (parameterSpec != null && !parameterSpec.isEmpty()) {
            params.put("parameterSpec", parameterSpec);
        }

        var keyPairResult = KeyPairGenerator.generateKeyPair(params);
        if (keyPairResult.failed()) {
            System.out.printf("| %s | %s-%s | ERROR: %s | - | - | - | - |%n",
                    family, algorithm, parameterSpec, keyPairResult.getFailureDetail());
            return;
        }

        var kp = keyPairResult.getContent();

        int pubSize = kp.getPublic().getEncoded().length;
        int privSize = kp.getPrivate().getEncoded().length;

        byte[] msg = "Validation message for Thesis - Identity Hub".getBytes(StandardCharsets.UTF_8);
        byte[] signature = sign(algorithm, kp.getPrivate(), msg);
        int sigSize = signature.length;

        int jwtSize = estimateJwtSize(signature);
        String safety = jwtSize > 8192 ? "❌ NO (>8KB)" : (jwtSize > 4096 ? "⚠️ RISK" : "✅ YES");

        System.out.printf("| %s | %s-%s | %d | %d | %d | %d | %s |%n",
                family, algorithm, parameterSpec, pubSize, privSize, sigSize, jwtSize, safety);
    }

    private static Stream<Arguments> provideAllVariants() {
        // Separamos el algoritmo de su especificación para encajar con la nueva arquitectura
        return Stream.of(
                Arguments.of("Dilithium", "DILITHIUM", "2"),
                Arguments.of("Dilithium", "DILITHIUM", "3"),
                Arguments.of("Dilithium", "DILITHIUM", "5"),
                Arguments.of("Falcon", "FALCON", "512"),
                Arguments.of("Falcon", "FALCON", "1024"),
                Arguments.of("SPHINCS+ (SHA2)", "SPHINCS", "sha2-128s-simple"),
                Arguments.of("SPHINCS+ (SHA2)", "SPHINCS", "sha2-128f-simple"),
                Arguments.of("SPHINCS+ (SHA2)", "SPHINCS", "sha2-256s-simple"),
                Arguments.of("SPHINCS+ (SHA2)", "SPHINCS", "sha2-256f-simple"),
                Arguments.of("SPHINCS+ (SHAKE)", "SPHINCS", "shake-128s-simple"),
                Arguments.of("SPHINCS+ (SHAKE)", "SPHINCS", "shake-128f-simple")
        );
    }

    private byte[] sign(String algo, java.security.PrivateKey key, byte[] msg) throws Exception {
        // BouncyCastle espera nombres genéricos para instanciar la firma (Dilithium, Falcon, SPHINCSPlus)
        // Ya no hace falta el split porque el algo viene limpio ("DILITHIUM", "FALCON", etc.)
        String sigAlgo = algo;
        if (algo.equalsIgnoreCase("SPHINCS")) {
            sigAlgo = "SPHINCSPlus";
        }

        java.security.Signature sig = java.security.Signature.getInstance(sigAlgo, "BCPQC");
        sig.initSign(key);
        sig.update(msg);
        return sig.sign();
    }

    private int estimateJwtSize(byte[] signature) {
        var encoder = Base64.getUrlEncoder().withoutPadding();
        String mockContent = "header.payload";
        return mockContent.length() + 1 + encoder.encodeToString(signature).length();
    }
}