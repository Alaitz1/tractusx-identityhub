import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.eclipse.tractusx.identityhub.pqc.KeyPairGenerator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.Security;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

class PqcPerformanceBenchmarkTest {

    @BeforeAll
    static void setup() {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
    }

    @Test
    void runFullBenchmark() {
        System.out.println("### POST-QUANTUM CRYPTOGRAPHY (PQC) BENCHMARK");
        System.out.println("| Family | Variant | Gen Time (ms) | Pub Size (B) | Priv Size (B) |");
        System.out.println("| :--- | :--- | :---: | :---: | :---: |");

        Map<String, List<String>> categories = new LinkedHashMap<>();

        categories.put("Classic", List.of("RSA-2048", "RSA-4096"));
        categories.put("Dilithium", List.of("DILITHIUM2", "DILITHIUM3", "DILITHIUM5"));
        categories.put("Falcon", List.of("Falcon-512", "Falcon-1024"));
        categories.put("SPHINCS+ (SHA2)", List.of(
                "SPHINCSPlus-SHA2-128s-simple", "SPHINCSPlus-SHA2-128f-simple",
                "SPHINCSPlus-SHA2-192s-simple", "SPHINCSPlus-SHA2-192f-simple",
                "SPHINCSPlus-SHA2-256s-simple", "SPHINCSPlus-SHA2-256f-simple"
        ));
        categories.put("SPHINCS+ (SHAKE)", List.of(
                "SPHINCSPlus-SHAKE-128s-simple", "SPHINCSPlus-SHAKE-128f-simple",
                "SPHINCSPlus-SHAKE-192s-simple", "SPHINCSPlus-SHAKE-192f-simple",
                "SPHINCSPlus-SHAKE-256s-simple", "SPHINCSPlus-SHAKE-256f-simple"
        ));

        categories.forEach((family, algos) -> {
            algos.forEach(algo -> {
                try {
                    Map<String, Object> params = new HashMap<>();
                    params.put("algorithm", algo);
                    if (algo.startsWith("RSA")) {
                        params.put("length", Integer.parseInt(algo.split("-")[1]));
                        params.put("algorithm", "RSA");
                    }

                    KeyPairGenerator.generateKeyPair(params);

                    long start = System.nanoTime();
                    int iterations = algo.contains("s-simple") ? 2 : 5;
                    KeyPair kp = null;
                    for (int i = 0; i < iterations; i++) {
                        kp = KeyPairGenerator.generateKeyPair(params).getContent();
                    }
                    long end = System.nanoTime();
                    long avgTime = (end - start) / iterations / 1_000_000;

                    int pubSize = kp.getPublic().getEncoded().length;
                    int privSize = kp.getPrivate().getEncoded().length;

                    System.out.printf("| %s | %s | %d ms | %d | %d |%n",
                            family, algo, avgTime, pubSize, privSize);

                } catch (Exception e) {
                    System.out.printf("| %s | %s | ERROR | - | - |%n", family, algo);
                }
            });
        });
    }
}