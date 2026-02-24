package org.eclipse.tractusx.identityhub.pqc;

import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;
import org.eclipse.edc.spi.result.Result;
import org.jetbrains.annotations.NotNull;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.List;
import java.util.Map;

public class KeyPairGenerator {
    public static final String ALGORITHM_RSA = "RSA";
    public static final String ALGORITHM_EC = "EC";
    public static final String ALGORITHM_EDDSA = "EDDSA";

    public static final String ALGORITHM_DILITHIUM = "DILITHIUM";
    public static final String ALGORITHM_FALCON = "FALCON";
    public static final String ALGORITHM_SPHINCS = "SPHINCS";

    public static final String CURVE_ED25519 = "ed25519";
    public static final String CURVE_X25519 = "x25519";

    public static final List<String> SUPPORTED_ALGORITHMS = List.of(
            ALGORITHM_EC, ALGORITHM_RSA, ALGORITHM_EDDSA,
            ALGORITHM_DILITHIUM, ALGORITHM_FALCON, ALGORITHM_SPHINCS
    );

    public static final List<String> SUPPORTED_EDDSA_CURVES = List.of(CURVE_ED25519, CURVE_X25519);
    public static final int RSA_DEFAULT_LENGTH = 2048;
    private static final String RSA_PARAM_LENGTH = "length";
    private static final String EC_PARAM_CURVE = "curve";
    private static final String EC_DEFAULT_CURVE = "secp256r1";
    private static final String ALGORITHM_ENTRY = "algorithm";
    private static final String PQC_PARAM_SPEC = "parameterSpec";

    public static Result<KeyPair> generateKeyPair(Map<String, Object> parameters) {
        var algorithmObj = parameters.get(ALGORITHM_ENTRY);
        if (algorithmObj == null) {
            return generateEdDsa(CURVE_ED25519);
        }

        var algorithm = algorithmObj.toString().toUpperCase();

        if (algorithm.startsWith(ALGORITHM_DILITHIUM) ||
                algorithm.startsWith(ALGORITHM_FALCON) ||
                algorithm.startsWith(ALGORITHM_SPHINCS)) {
            return generatePqc(algorithm, parameters.getOrDefault(PQC_PARAM_SPEC, "").toString());
        }

        if (SUPPORTED_ALGORITHMS.contains(algorithm)) {
            return switch (algorithm) {
                case ALGORITHM_RSA -> generateRsa(Integer.parseInt(parameters.getOrDefault(RSA_PARAM_LENGTH, RSA_DEFAULT_LENGTH).toString()));
                case ALGORITHM_EC -> generateEc(parameters.getOrDefault(EC_PARAM_CURVE, EC_DEFAULT_CURVE).toString());
                case ALGORITHM_EDDSA -> generateEdDsa(parameters.getOrDefault(EC_PARAM_CURVE, CURVE_ED25519).toString());
                default -> Result.failure("Unsupported algorithm: " + algorithm);
            };
        }
        return Result.failure("Unsupported algorithm: " + algorithm);
    }

    private static Result<KeyPair> generatePqc(String algorithm, String parameterSpec) {
        try {
            String bcName = mapToBouncyCastleName(algorithm);
            var gen = java.security.KeyPairGenerator.getInstance(bcName, "BCPQC");
            if (parameterSpec != null && !parameterSpec.trim().isEmpty()) {
                // Aquí aplicamos las clases correctas de BouncyCastle en vez de ECGenParameterSpec
                gen.initialize(getBcPqcSpec(algorithm, parameterSpec), new SecureRandom());
            }

            return Result.success(gen.generateKeyPair());
        } catch (Exception e) {
            return Result.failure("PQC Error: " + e.getMessage());
        }
    }

    // Traductor a Clases de BouncyCastle
    private static AlgorithmParameterSpec getBcPqcSpec(String algo, String spec) {
        String a = algo.toUpperCase();
        String s = spec.toLowerCase();

        if (a.contains("DILITHIUM")) {
            if (s.contains("2")) return DilithiumParameterSpec.dilithium2;
            if (s.contains("3")) return DilithiumParameterSpec.dilithium3;
            if (s.contains("5")) return DilithiumParameterSpec.dilithium5;
            return DilithiumParameterSpec.dilithium2;
        }

        if (a.contains("FALCON")) {
            if (s.contains("512")) return FalconParameterSpec.falcon_512;
            if (s.contains("1024")) return FalconParameterSpec.falcon_1024;
            return FalconParameterSpec.falcon_512;
        }

        if (a.contains("SPHINCS")) {
            if (s.contains("sha2-128s")) return SPHINCSPlusParameterSpec.sha2_128s;
            if (s.contains("sha2-128f")) return SPHINCSPlusParameterSpec.sha2_128f;
            if (s.contains("sha2-192s")) return SPHINCSPlusParameterSpec.sha2_192s;
            if (s.contains("sha2-192f")) return SPHINCSPlusParameterSpec.sha2_192f;
            if (s.contains("sha2-256s")) return SPHINCSPlusParameterSpec.sha2_256s;
            if (s.contains("sha2-256f")) return SPHINCSPlusParameterSpec.sha2_256f;
            if (s.contains("shake-128s")) return SPHINCSPlusParameterSpec.shake_128s;
            if (s.contains("shake-128f")) return SPHINCSPlusParameterSpec.shake_128f;
            if (s.contains("shake-192s")) return SPHINCSPlusParameterSpec.shake_192s;
            if (s.contains("shake-192f")) return SPHINCSPlusParameterSpec.shake_192f;
            if (s.contains("shake-256s")) return SPHINCSPlusParameterSpec.shake_256s;
            if (s.contains("shake-256f")) return SPHINCSPlusParameterSpec.shake_256f;
            return SPHINCSPlusParameterSpec.sha2_128s;
        }

        throw new IllegalArgumentException("Unsupported PQC spec: " + algo + " / " + spec);
    }

    private static String mapToBouncyCastleName(String algo) {
        String a = algo.toUpperCase();
        if (a.startsWith("FALCON")) return "Falcon";
        if (a.startsWith("DILITHIUM")) return "Dilithium";
        if (a.startsWith("SPHINCS")) return "SPHINCSPlus";
        return algo;
    }

    private static Result<KeyPair> generateEc(String stdName) {
        try {
            var javaGenerator = java.security.KeyPairGenerator.getInstance(ALGORITHM_EC);
            javaGenerator.initialize(new ECGenParameterSpec(stdName));
            return Result.success(javaGenerator.generateKeyPair());
        } catch (NoSuchAlgorithmException e) {
            return Result.failure("Error generating EC keys: " + e);
        } catch (InvalidAlgorithmParameterException e) {
            return Result.failure("Error generating EC keys: %s is not a valid EC curve.".formatted(stdName));
        }
    }

    private static Result<KeyPair> generateEdDsa(@NotNull String curve) {
        var lowerCurve = curve.toLowerCase();
        if (SUPPORTED_EDDSA_CURVES.contains(lowerCurve)) {
            try {
                var javaGenerator = java.security.KeyPairGenerator.getInstance(lowerCurve);
                return Result.success(javaGenerator.generateKeyPair());
            } catch (NoSuchAlgorithmException e) {
                return Result.failure("Error generating EdDSA keys: " + e);
            }
        }
        return Result.failure("Unsupported EdDSA Curve: " + lowerCurve);
    }

    private static Result<KeyPair> generateRsa(int length) {
        try {
            var javaGenerator = java.security.KeyPairGenerator.getInstance(ALGORITHM_RSA);
            javaGenerator.initialize(length, new SecureRandom());
            return Result.success(javaGenerator.generateKeyPair());
        } catch (NoSuchAlgorithmException e) {
            return Result.failure("Error generating RSA keys: " + e);
        }
    }
}