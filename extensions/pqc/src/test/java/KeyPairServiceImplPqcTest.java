
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.eclipse.edc.identityhub.spi.keypair.events.KeyPairObservable;
import org.eclipse.edc.identityhub.spi.keypair.model.KeyPairResource;
import org.eclipse.edc.identityhub.spi.keypair.model.KeyPairState;
import org.eclipse.edc.identityhub.spi.keypair.store.KeyPairResourceStore;
import org.eclipse.edc.identityhub.spi.participantcontext.model.KeyDescriptor;
import org.eclipse.edc.identityhub.spi.participantcontext.model.ParticipantContext;
import org.eclipse.edc.identityhub.spi.participantcontext.store.ParticipantContextStore;
import org.eclipse.edc.spi.monitor.Monitor;
import org.eclipse.edc.spi.query.QuerySpec;
import org.eclipse.edc.spi.result.StoreResult;
import org.eclipse.edc.spi.security.Vault;
import org.eclipse.edc.transaction.spi.TransactionContext;
import org.eclipse.tractusx.identityhub.pqc.KeyPairServiceImpl;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatCode;
import static org.eclipse.edc.identityhub.spi.participantcontext.model.ParticipantContextState.ACTIVATED;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class KeyPairServiceImplPqcTest {

    private static final String PARTICIPANT_ID = "participant-123";
    private static final String KEY_ID = "test-key-id";
    private static final String PRIVATE_KEY_ALIAS = "test-private-alias";

    private KeyPairServiceImpl keyPairService;
    private KeyPairResourceStore keyPairResourceStore;
    private Vault vault;
    private ObjectMapper objectMapper;

    @BeforeAll
    static void setUpBouncyCastle() {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
    }

    @BeforeEach
    void setUp() {
        keyPairResourceStore = mock(KeyPairResourceStore.class);
        vault = mock(Vault.class);
        var participantContextStore = mock(ParticipantContextStore.class);
        objectMapper = new ObjectMapper();

        var transactionContext = new TransactionContext() {
            @Override public void execute(TransactionBlock b) {
                b.execute();
            }

            @Override public <T> T execute(ResultTransactionBlock<T> b) {
                return b.execute();
            }

            @Override public void registerSynchronization(TransactionSynchronization s) {}
        };

        keyPairService = new KeyPairServiceImpl(
                keyPairResourceStore, vault, mock(Monitor.class), mock(KeyPairObservable.class),
                transactionContext, participantContextStore
        );

        var participantContext = ParticipantContext.Builder.newInstance()
                .participantContextId(PARTICIPANT_ID).apiTokenAlias("test-api-token-alias").state(ACTIVATED).build();

        when(participantContextStore.query(any(QuerySpec.class))).thenReturn(StoreResult.success(List.of(participantContext)));
        when(keyPairResourceStore.create(any(KeyPairResource.class))).thenReturn(StoreResult.success());
        when(keyPairResourceStore.update(any(KeyPairResource.class))).thenReturn(StoreResult.success());
        when(keyPairResourceStore.query(any(QuerySpec.class))).thenReturn(StoreResult.success(Collections.emptyList()));
        when(vault.storeSecret(anyString(), anyString())).thenReturn(org.eclipse.edc.spi.result.Result.success());
    }

    @Test
    @DisplayName("BouncyCastle PQC is available")
    void testBouncyCastlePqcAvailable() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DILITHIUM2", "BCPQC");
        KeyPair keyPair = keyGen.generateKeyPair();
        assertThat(keyPair).isNotNull();
        assertThat(keyPair.getPublic()).isNotNull();
        assertThat(keyPair.getPrivate()).isNotNull();
    }

    // ========== DILITHIUM TESTS ==========

    @ParameterizedTest
    @MethodSource("provideDilithiumVariants")
    void testDilithiumVariants_JwkFormat(String algorithm, String spec, String expectedAlgName) {
        assertValidJwkGeneration(algorithm, spec, expectedAlgName);
    }

    static Stream<Arguments> provideDilithiumVariants() {
        return Stream.of(Arguments.of("DILITHIUM", "2", "ML-DSA-44"), Arguments.of("DILITHIUM", "3", "ML-DSA-65"), Arguments.of("DILITHIUM", "5", "ML-DSA-87"));
    }

    @Test
    void testDilithium2_PemFormat() {
        assertValidPemGeneration("DILITHIUM", "2");
    }

    @Test
    void testDilithium3_Base64Format() {
        assertValidBase64Generation("DILITHIUM", "3");
    }

    // ========== FALCON TESTS ==========

    @ParameterizedTest
    @MethodSource("provideFalconVariants")
    void testFalconVariants_JwkFormat(String algorithm, String spec, String expectedAlgName) {
        assertValidJwkGeneration(algorithm, spec, expectedAlgName);
    }

    static Stream<Arguments> provideFalconVariants() {
        return Stream.of(Arguments.of("Falcon", "512", "FALCON-512"), Arguments.of("Falcon", "1024", "FALCON-1024"));
    }

    @Test
    void testFalcon512_PemFormat() {
        assertValidPemGeneration("Falcon", "512");
    }

    @Test
    void testFalcon1024_Base64Format() {
        assertValidBase64Generation("Falcon", "1024");
    }

    // ========== SPHINCS+ TESTS ==========

    @ParameterizedTest
    @MethodSource("provideSphincsVariants")
    void testSphincsVariants_JwkFormat(String algorithm, String spec, String expectedAlgName) {
        assertValidJwkGeneration(algorithm, spec, expectedAlgName);
    }

    static Stream<Arguments> provideSphincsVariants() {
        return Stream.of(Arguments.of("SPHINCSPlus", "sha2-128s-simple", "SLH-DSA-SHA2-128s"), Arguments.of("SPHINCSPlus", "sha2-256f-simple", "SLH-DSA-SHA2-256f"), Arguments.of("SPHINCSPlus", "shake-128s-simple", "SLH-DSA-SHAKE-128s"));
    }

    @Test
    void testSphincs_PemFormat() {
        assertValidPemGeneration("SPHINCSPlus", "sha2-128s-simple");
    }

    // ========== HYBRID & NEGATIVE TESTS ==========

    @Test
    void testHybridGeneration() {
        var result = keyPairService.addKeyPair(PARTICIPANT_ID, createKeyDescriptor("HYBRID", null, "jwk"), true);
        assertThat(result.succeeded()).isTrue();

        verify(keyPairResourceStore).create(argThat(resource -> {
            try {
                var jwk = objectMapper.readValue(resource.getSerializedPublicKey(), Map.class);
                var classic = (Map<?, ?>) jwk.get("classical");
                var pqc = (Map<?, ?>) jwk.get("postQuantum");
                return "OKP".equals(classic.get("kty")) && "AKP".equals(pqc.get("kty"));
            } catch (Exception e) {
                return false;
            }
        }));

        verify(vault).storeSecret(eq(PRIVATE_KEY_ALIAS + "-classic"), anyString());
        verify(vault).storeSecret(eq(PRIVATE_KEY_ALIAS + "-pqc"), anyString());
    }

    @ParameterizedTest
    @ValueSource(strings = {"DILITHIUM-999", "FALCON-256", "SPHINCS-INVALID"})
    void testInvalidPqcVariants_ShouldFail(String invalidSpec) {
        var result = keyPairService.addKeyPair(PARTICIPANT_ID, createKeyDescriptor("DILITHIUM", invalidSpec, "jwk"), true);
        assertThat(result.failed()).isTrue();
        assertThat(result.getFailureDetail()).contains("Invalid PQC configuration");
    }

    @Test
    void testPrivateKeyStorageInVault() {
        var result = keyPairService.addKeyPair(PARTICIPANT_ID, createKeyDescriptor("Falcon", "512", "jwk"), true);
        assertThat(result.succeeded()).isTrue();
        verify(vault).storeSecret(eq(PRIVATE_KEY_ALIAS), argThat(privateKey -> {
            assertThatCode(() -> Base64.getDecoder().decode(privateKey)).doesNotThrowAnyException();
            return true;
        }));
    }

    @Test
    void testJwkUsesBase64UrlEncoding() {
        var result = keyPairService.addKeyPair(PARTICIPANT_ID, createKeyDescriptor("Falcon", "512", "jwk"), true);
        assertThat(result.succeeded()).isTrue();
        verify(keyPairResourceStore).create(argThat(resource -> {
            try {
                var jwk = objectMapper.readValue(resource.getSerializedPublicKey(), Map.class);
                String pub = (String) jwk.get("pub");
                return !pub.contains("+") && !pub.contains("/") && !pub.contains("=") && pub.matches("^[A-Za-z0-9_-]+$");
            } catch (Exception e) {
                return false;
            }
        }));
    }

    @Test
    void testActiveKeyPair() {
        var result = keyPairService.addKeyPair(PARTICIPANT_ID, createKeyDescriptor("DILITHIUM", "2", "jwk"), true);
        assertThat(result.succeeded()).isTrue();
        verify(keyPairResourceStore).create(argThat(r -> r.getState() == KeyPairState.ACTIVATED.code()));
    }

    @Test
    void testInactiveKeyPair() {
        var mockResource = KeyPairResource.Builder.newInstance().id("k1").keyId("k2").state(KeyPairState.ACTIVATED.code())
                .privateKeyAlias("a").serializedPublicKey("pub").timestamp(1L).participantContextId(PARTICIPANT_ID)
                .keyContext("Pqc").build();

        when(keyPairResourceStore.query(any(QuerySpec.class))).thenReturn(StoreResult.success(List.of(mockResource)));
        var result = keyPairService.addKeyPair(PARTICIPANT_ID, createKeyDescriptor("DILITHIUM", "2", "jwk", false), false);

        assertThat(result.succeeded()).isTrue();
        verify(keyPairResourceStore).create(argThat(r -> r.getState() == KeyPairState.CREATED.code()));
    }

    // ========== HELPER METHODS ==========

    private void assertValidJwkGeneration(String algorithm, String spec, String expectedAlgName) {
        var result = keyPairService.addKeyPair(PARTICIPANT_ID, createKeyDescriptor(algorithm, spec, "jwk"), true);
        assertThat(result.succeeded()).isTrue();
        verify(keyPairResourceStore).create(argThat(resource -> {
            try {
                var jwk = objectMapper.readValue(resource.getSerializedPublicKey(), Map.class);
                return "AKP".equals(jwk.get("kty")) && expectedAlgName.equals(jwk.get("alg")) &&
                        KEY_ID.equals(jwk.get("kid")) && "sig".equals(jwk.get("use")) &&
                        jwk.get("pub") != null && !jwk.containsKey("crv") && !jwk.containsKey("x");
            } catch (Exception e) {
                return false;
            }
        }));
    }

    private void assertValidPemGeneration(String algorithm, String spec) {
        var result = keyPairService.addKeyPair(PARTICIPANT_ID, createKeyDescriptor(algorithm, spec, "pem"), true);
        assertThat(result.succeeded()).isTrue();
        verify(keyPairResourceStore).create(argThat(resource -> {
            String pem = resource.getSerializedPublicKey();
            return pem.startsWith("-----BEGIN PUBLIC KEY-----") && pem.endsWith("-----END PUBLIC KEY-----");
        }));
    }

    private void assertValidBase64Generation(String algorithm, String spec) {
        var result = keyPairService.addKeyPair(PARTICIPANT_ID, createKeyDescriptor(algorithm, spec, "base64"), true);
        assertThat(result.succeeded()).isTrue();
        verify(keyPairResourceStore).create(argThat(resource -> {
            String b64 = resource.getSerializedPublicKey();
            assertThatCode(() -> Base64.getDecoder().decode(b64)).doesNotThrowAnyException();
            return b64.matches("^[A-Za-z0-9+/]+=*$");
        }));
    }

    private KeyDescriptor createKeyDescriptor(String algo, String spec, String format) {
        return createKeyDescriptor(algo, spec, format, true);
    }

    private KeyDescriptor createKeyDescriptor(String algorithm, String parameterSpec, String format, boolean active) {
        Map<String, Object> params = new HashMap<>();
        params.put("algorithm", algorithm);
        if (parameterSpec != null && !parameterSpec.isEmpty()) params.put("parameterSpec", parameterSpec);
        params.put("format", format);

        return KeyDescriptor.Builder.newInstance()
                .keyId(KEY_ID).privateKeyAlias(PRIVATE_KEY_ALIAS).resourceId("res-" + algorithm)
                .active(active).type("PqcVerificationKey2026").keyGeneratorParams(params).build();
    }
}