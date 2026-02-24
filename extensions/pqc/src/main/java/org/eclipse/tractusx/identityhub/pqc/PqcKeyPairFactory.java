package org.eclipse.tractusx.identityhub.pqc;

import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;


public class PqcKeyPairFactory {

    private static final String DEFAULT_CLASSICAL_ALGO = "Ed25519";
    private static final String DEFAULT_PQC_ALGO = "Dilithium";
    private static final String PQC_PROVIDER = "BCPQC";

    /**
     * Genera un par de claves híbridas de forma dinámica.
     */
    public static HybridKeyPair generate(String classicalAlgo, String classicalSpec, String pqcAlgo, String pqcSpec) throws Exception {
        KeyPairGenerator classicalGen = KeyPairGenerator.getInstance(classicalAlgo);
        if (classicalSpec != null && !classicalSpec.trim().isEmpty() && classicalAlgo.equalsIgnoreCase("EC")) {
            classicalGen.initialize(new ECGenParameterSpec(classicalSpec));
        }

        KeyPair classicalKeyPair = classicalGen.generateKeyPair();

        KeyPairGenerator pqcGen = KeyPairGenerator.getInstance(pqcAlgo, PQC_PROVIDER);
        if (pqcSpec != null && !pqcSpec.trim().isEmpty()) {

            pqcGen.initialize(getBcPqcSpec(pqcAlgo, pqcSpec));
        }
        KeyPair pqcKeyPair = pqcGen.generateKeyPair();

        return new HybridKeyPair(classicalKeyPair, pqcKeyPair);
    }

    public static HybridKeyPair generateDefaultSsiHybrid() throws Exception {
        return generate(DEFAULT_CLASSICAL_ALGO, null, DEFAULT_PQC_ALGO, "dilithium5");
    }

    /**
     * Convierte los nombres en formato String a las clases nativas de BouncyCastle.
     */
    private static AlgorithmParameterSpec getBcPqcSpec(String algo, String spec) {
        String a = algo.toUpperCase();
        String s = spec.toLowerCase();

        if (a.contains("DILITHIUM")) {
            if (s.contains("2")) return DilithiumParameterSpec.dilithium2;
            if (s.contains("3")) return DilithiumParameterSpec.dilithium3;
            if (s.contains("5")) return DilithiumParameterSpec.dilithium5;
            return DilithiumParameterSpec.dilithium2; // Default fallback
        }

        if (a.contains("FALCON")) {
            if (s.contains("512")) return FalconParameterSpec.falcon_512;
            if (s.contains("1024")) return FalconParameterSpec.falcon_1024;
            return FalconParameterSpec.falcon_512; // Default fallback
        }

        throw new IllegalArgumentException("Unsupported PQC algorithm or spec for generation: " + algo + " / " + spec);
    }
}
