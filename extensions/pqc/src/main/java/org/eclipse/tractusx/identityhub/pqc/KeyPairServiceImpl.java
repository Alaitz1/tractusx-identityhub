package org.eclipse.tractusx.identityhub.pqc;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.eclipse.edc.identityhub.spi.keypair.KeyPairService;
import org.eclipse.edc.identityhub.spi.keypair.events.KeyPairObservable;
import org.eclipse.edc.identityhub.spi.keypair.model.KeyPairResource;
import org.eclipse.edc.identityhub.spi.keypair.model.KeyPairState;
import org.eclipse.edc.identityhub.spi.keypair.store.KeyPairResourceStore;
import org.eclipse.edc.identityhub.spi.participantcontext.events.ParticipantContextCreated;
import org.eclipse.edc.identityhub.spi.participantcontext.events.ParticipantContextDeleted;
import org.eclipse.edc.identityhub.spi.participantcontext.model.KeyDescriptor;
import org.eclipse.edc.identityhub.spi.participantcontext.model.ParticipantContextState;
import org.eclipse.edc.identityhub.spi.participantcontext.store.ParticipantContextStore;
import org.eclipse.edc.security.token.jwt.CryptoConverter;
import org.eclipse.edc.spi.event.Event;
import org.eclipse.edc.spi.event.EventEnvelope;
import org.eclipse.edc.spi.event.EventSubscriber;
import org.eclipse.edc.spi.monitor.Monitor;
import org.eclipse.edc.spi.query.Criterion;
import org.eclipse.edc.spi.query.QuerySpec;
import org.eclipse.edc.spi.result.AbstractResult;
import org.eclipse.edc.spi.result.Result;
import org.eclipse.edc.spi.result.ServiceResult;
import org.eclipse.edc.spi.result.StoreResult;
import org.eclipse.edc.spi.security.Vault;
import org.eclipse.edc.transaction.spi.TransactionContext;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.security.PublicKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.eclipse.edc.identityhub.spi.participantcontext.model.ParticipantContextState.ACTIVATED;
import static org.eclipse.edc.identityhub.spi.participantcontext.model.ParticipantContextState.CREATED;
import static org.eclipse.edc.identityhub.spi.participantcontext.model.ParticipantResource.queryByParticipantContextId;

public class KeyPairServiceImpl implements KeyPairService, EventSubscriber {
    private final KeyPairResourceStore keyPairResourceStore;
    private final Vault vault;
    private final Monitor monitor;
    private final KeyPairObservable observable;
    private final TransactionContext transactionContext;
    private final ParticipantContextStore participantContextService;

    public KeyPairServiceImpl(KeyPairResourceStore keyPairResourceStore, Vault vault, Monitor monitor, KeyPairObservable observable, TransactionContext transactionContext, ParticipantContextStore participantContextService) {
        this.keyPairResourceStore = keyPairResourceStore;
        this.vault = vault;
        this.monitor = monitor;
        this.observable = observable;
        this.transactionContext = transactionContext;
        this.participantContextService = participantContextService;
    }

    @Override
    public ServiceResult<Void> addKeyPair(String participantContextId, KeyDescriptor keyDescriptor, boolean makeDefault) {

        return transactionContext.execute(() -> {

            var result = checkParticipantState(participantContextId, ACTIVATED, CREATED);

            if (result.failed()) {
                return result.mapEmpty();
            }

            var key = generateOrGetKey(keyDescriptor);
            if (key.failed()) {
                return ServiceResult.badRequest(key.getFailureDetail());
            }

            if (!keyDescriptor.isActive()) {
                var hasActiveKeys = keyPairResourceStore.query(queryByParticipantContextId(participantContextId).build())
                        .orElse(failure -> Collections.emptySet())
                        .stream().filter(kpr -> kpr.getState() == KeyPairState.ACTIVATED.code())
                        .findAny()
                        .isEmpty();

                if (!hasActiveKeys) {
                    monitor.warning("Participant '%s' has no active key pairs, and adding an inactive one will prevent the participant from becoming operational.");
                }
            }

            var newResource = KeyPairResource.Builder.newInstance()
                    .id(keyDescriptor.getResourceId())
                    .keyId(keyDescriptor.getKeyId())
                    .state(keyDescriptor.isActive() ? KeyPairState.ACTIVATED : KeyPairState.CREATED)
                    .isDefaultPair(makeDefault)
                    .privateKeyAlias(keyDescriptor.getPrivateKeyAlias())
                    .serializedPublicKey(key.getContent())
                    .timestamp(Instant.now().toEpochMilli())
                    .participantContextId(participantContextId)
                    .keyContext(keyDescriptor.getType())
                    .build();

            return ServiceResult.from(keyPairResourceStore.create(newResource))
                    .onSuccess(v -> observable.invokeForEach(l -> l.added(newResource, keyDescriptor.getType())))
                    .compose(v -> {
                        if (keyDescriptor.isActive()) {
                            return activateKeyPair(newResource);
                        }
                        return ServiceResult.success();
                    });
        });
    }

    @Override
    public ServiceResult<Void> rotateKeyPair(String oldId, @Nullable KeyDescriptor newKeyDesc, long duration) {
        return transactionContext.execute(() -> {
            var oldKey = findById(oldId);
            if (oldKey == null) {
                return ServiceResult.notFound("A KeyPairResource with ID '%s' does not exist.".formatted(oldId));
            }

            var participantContextId = oldKey.getParticipantContextId();
            boolean wasDefault = oldKey.isDefaultPair();

            var oldAlias = oldKey.getPrivateKeyAlias();
            vault.deleteSecret(oldAlias);
            // También deberíamos considerar limpiar los alias compuestos si era híbrida,
            // pero por simplicidad de EDC se asume que borra el principal.
            vault.deleteSecret(oldAlias + "-classic");
            vault.deleteSecret(oldAlias + "-pqc");

            oldKey.rotate(duration);
            var updateResult = ServiceResult.from(keyPairResourceStore.update(oldKey))
                    .onSuccess(v -> observable.invokeForEach(l -> l.rotated(oldKey, newKeyDesc)));

            if (newKeyDesc != null) {
                return updateResult.compose(v -> addKeyPair(participantContextId, newKeyDesc, wasDefault));
            }
            monitor.warning("Rotating keys without a successor key may leave the participant without an active keypair.");
            return updateResult;
        });
    }

    @Override
    public ServiceResult<Void> revokeKey(String id, @Nullable KeyDescriptor newKeyDesc) {
        return transactionContext.execute(() -> {
            var oldKey = findById(id);
            if (oldKey == null) {
                return ServiceResult.notFound("A KeyPairResource with ID '%s' does not exist.".formatted(id));
            }

            var participantContextId = oldKey.getParticipantContextId();
            boolean wasDefault = oldKey.isDefaultPair();

            var oldAlias = oldKey.getPrivateKeyAlias();
            vault.deleteSecret(oldAlias);
            vault.deleteSecret(oldAlias + "-classic");
            vault.deleteSecret(oldAlias + "-pqc");

            oldKey.revoke();
            var updateResult = ServiceResult.from(keyPairResourceStore.update(oldKey))
                    .onSuccess(v -> observable.invokeForEach(l -> l.revoked(oldKey, newKeyDesc)));

            if (newKeyDesc != null) {
                return updateResult.compose(v -> addKeyPair(participantContextId, newKeyDesc, wasDefault));
            }
            monitor.warning("Revoking keys without a successor key may leave the participant without an active keypair.");
            return updateResult;
        });
    }

    @Override
    public ServiceResult<Collection<KeyPairResource>> query(QuerySpec querySpec) {
        return ServiceResult.from(keyPairResourceStore.query(querySpec));
    }

    @Override
    public ServiceResult<Void> activate(String keyPairResourceId) {
        return transactionContext.execute(() -> {
            var existingKeyPair = findById(keyPairResourceId);
            if (existingKeyPair == null) {
                return ServiceResult.notFound("A KeyPairResource with ID '%s' does not exist.".formatted(keyPairResourceId));
            }

            return activateKeyPair(existingKeyPair);
        });
    }

    @Override
    public <E extends Event> void on(EventEnvelope<E> eventEnvelope) {
        var payload = eventEnvelope.getPayload();
        if (payload instanceof ParticipantContextDeleted deleted) {
            deleted(deleted);
        } else {
            monitor.warning("Received event with unexpected payload type: %s".formatted(payload.getClass()));
        }
    }

    private ServiceResult<Void> checkParticipantState(String participantContextId, ParticipantContextState... allowedStates) {
        var result = ServiceResult.from(participantContextService.query(queryByParticipantContextId(participantContextId).build()))
                .compose(list -> list.stream().findFirst()
                        .map(pc -> {
                            var state = pc.getStateAsEnum();
                            if (!Arrays.asList(allowedStates).contains(state)) {
                                return ServiceResult.badRequest("To add a key pair, the ParticipantContext with ID '%s' must be in state %s or %s but was %s."
                                        .formatted(participantContextId, ACTIVATED, CREATED, state));
                            }
                            return ServiceResult.success();
                        })
                        .orElse(ServiceResult.notFound("No ParticipantContext with ID '%s' was found.".formatted(participantContextId))));
        return result.mapEmpty();
    }

    private @NotNull ServiceResult<Void> activateKeyPair(KeyPairResource existingKeyPair) {
        var allowedStates = List.of(KeyPairState.ACTIVATED.code(), KeyPairState.CREATED.code());
        if (!allowedStates.contains(existingKeyPair.getState())) {
            return ServiceResult.badRequest("The key pair resource is expected to be in %s, but was %s".formatted(allowedStates, existingKeyPair.getState()));
        }
        existingKeyPair.activate();

        return ServiceResult.from(keyPairResourceStore.update(existingKeyPair)
                .onSuccess(u -> observable.invokeForEach(l -> l.activated(existingKeyPair, existingKeyPair.getKeyContext()))));
    }

    private void created(ParticipantContextCreated event) {
        addKeyPair(event.getParticipantContextId(), event.getManifest().getKey(), true)
                .onFailure(f -> monitor.warning("Adding the key pair to a new ParticipantContext failed: %s".formatted(f.getFailureDetail())));
    }

    private void deleted(ParticipantContextDeleted event) {
        var query = queryByParticipantContextId(event.getParticipantContextId()).build();
        transactionContext.execute(() -> {
            keyPairResourceStore.query(query)
                    .compose(list -> {
                        var errors = list.stream()
                                .map(r -> keyPairResourceStore.deleteById(r.getId()))
                                .filter(StoreResult::failed)
                                .map(AbstractResult::getFailureDetail)
                                .collect(Collectors.joining(","));

                        if (errors.isEmpty()) {
                            return StoreResult.success();
                        }
                        return StoreResult.generalError("An error occurred when deleting KeyPairResources: %s".formatted(errors));
                    })
                    .onFailure(f -> monitor.warning("Removing key pairs from a deleted ParticipantContext failed: %s".formatted(f.getFailureDetail())));
        });
    }

    private KeyPairResource findById(String oldId) {
        var q = QuerySpec.Builder.newInstance()
                .filter(new Criterion("id", "=", oldId)).build();
        return keyPairResourceStore.query(q).map(list -> list.stream().findFirst().orElse(null)).orElse(f -> null);
    }

    private Result<String> generateOrGetKey(KeyDescriptor keyDescriptor) {
        var params = keyDescriptor.getKeyGeneratorParams();
        if (params == null) return getExistingKeyFallback(keyDescriptor);

        String algorithm = params.getOrDefault("algorithm", "").toString();

        if (algorithm.equalsIgnoreCase("HYBRID")) return generateHybridKey(keyDescriptor, params);
        if (isPqcAlgorithm(algorithm)) return generatePqcKey(keyDescriptor, params, algorithm);

        return generateClassicalKey(keyDescriptor, params);
    }

    private Result<String> generateHybridKey(KeyDescriptor keyDescriptor, Map<String, Object> params) {
        try {
            String pqcAlgo = params.getOrDefault("pqcAlgorithm", "DILITHIUM").toString();
            String pqcSpec = params.getOrDefault("pqcSpec", "dilithium5").toString();
            HybridKeyPair hybridKeys = PqcKeyPairFactory.generate("Ed25519", null, pqcAlgo, pqcSpec);

            vault.storeSecret(keyDescriptor.getPrivateKeyAlias() + "-classic", Base64.getEncoder().encodeToString(hybridKeys.getClassicalKeyPair().getPrivate().getEncoded()));
            vault.storeSecret(keyDescriptor.getPrivateKeyAlias() + "-pqc", Base64.getEncoder().encodeToString(hybridKeys.getPqcKeyPair().getPrivate().getEncoded()));

            com.nimbusds.jose.jwk.JWK classicJwk = CryptoConverter.createJwk(hybridKeys.getClassicalKeyPair(), keyDescriptor.getKeyId() + "-classic");
            String pqcJwkString = convertPqcToJwk(hybridKeys.getPqcKeyPair().getPublic(), keyDescriptor.getKeyId() + "-pqc", pqcAlgo, pqcSpec);

            return Result.success(String.format("{\"classical\": %s, \"postQuantum\": %s}", classicJwk.toPublicJWK().toJSONString(), pqcJwkString));
        } catch (Exception e) {
            return Result.failure("Failed to generate hybrid keys: " + e.getMessage());
        }
    }

    private Result<String> generatePqcKey(KeyDescriptor keyDescriptor, Map<String, Object> params, String algorithm) {
        String spec = params.getOrDefault("parameterSpec", "").toString();
        var validationResult = validatePqcVariant(algorithm, spec);
        if (validationResult.failed()) return validationResult.mapFailure();

        var keyPairResult = KeyPairGenerator.generateKeyPair(params);
        if (keyPairResult.failed()) return keyPairResult.mapFailure();

        var keyPair = keyPairResult.getContent();
        var format = params.getOrDefault("format", "base64").toString().toLowerCase();

        String publicKeySerialized = switch (format) {
            case "pem" -> encodePqcPublicKeyPem(keyPair.getPublic());
            case "jwk" -> convertPqcToJwk(keyPair.getPublic(), keyDescriptor.getKeyId(), algorithm, spec);
            default -> encodePqcPublicKeyBase64(keyPair.getPublic());
        };

        vault.storeSecret(keyDescriptor.getPrivateKeyAlias(), Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
        return Result.success(publicKeySerialized);
    }

    private Result<String> generateClassicalKey(KeyDescriptor keyDescriptor, Map<String, Object> params) {
        var keyPairResult = KeyPairGenerator.generateKeyPair(params);
        if (keyPairResult.failed()) return keyPairResult.mapFailure();

        var jwk = CryptoConverter.createJwk(keyPairResult.getContent(), keyDescriptor.getKeyId());
        vault.storeSecret(keyDescriptor.getPrivateKeyAlias(), jwk.toJSONString());
        return Result.success(jwk.toPublicJWK().toJSONString());
    }

    private Result<String> getExistingKeyFallback(KeyDescriptor keyDescriptor) {
        return Result.success(Optional.ofNullable(keyDescriptor.getPublicKeyJwk())
                .map(m -> CryptoConverter.create(m).toJSONString())
                .orElseGet(() -> keyDescriptor.getPublicKeyPem() != null
                        ? keyDescriptor.getPublicKeyPem().replace("\\n", "\n")
                        : ""));
    }

    private boolean isPqcAlgorithm(String algo) {
        if (algo == null) return false;
        String a = algo.toUpperCase();
        return a.contains("DILITHIUM") || a.startsWith("FALCON") || a.contains("SPHINCS");
    }

    private String encodePqcPublicKeyBase64(PublicKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    private String encodePqcPublicKeyPem(PublicKey key) {
        String base64Key = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(key.getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + base64Key + "\n-----END PUBLIC KEY-----";
    }

    private String convertPqcToJwk(PublicKey publicKey, String keyId, String algorithm, String spec) {
        byte[] rawKeyBytes = extractRawPublicKeyBytes(publicKey);
        var base64Url = Base64.getUrlEncoder().withoutPadding().encodeToString(rawKeyBytes);

        String algName = validatePqcVariant(algorithm, spec).getContent();

        return """
        {
          "kty": "AKP",
          "alg": "%s",
          "pub": "%s",
          "kid": "%s",
          "use": "sig"
        }
        """.formatted(algName, base64Url, keyId);
    }

    private byte[] extractRawPublicKeyBytes(PublicKey pub) {
        try {
            var spki = SubjectPublicKeyInfo.getInstance(pub.getEncoded());
            return spki.getPublicKeyData().getOctets();
        } catch (Exception e) {
            return pub.getEncoded();
        }
    }

    private Result<String> validatePqcVariant(String algorithm, String spec) {
        var algoUpper = algorithm.toUpperCase();
        var specStr = spec != null ? spec.toLowerCase() : "";

        if (algoUpper.startsWith("FALCON")) {
            if (specStr.equals("512") || specStr.equals("falcon-512")) return Result.success("FALCON-512");
            if (specStr.equals("1024") || specStr.equals("falcon-1024")) return Result.success("FALCON-1024");

        } else if (algoUpper.startsWith("DILITHIUM")) {
            if (specStr.equals("2") || specStr.equals("dilithium2") || specStr.isEmpty()) return Result.success("ML-DSA-44");
            if (specStr.equals("3") || specStr.equals("dilithium3")) return Result.success("ML-DSA-65");
            if (specStr.equals("5") || specStr.equals("dilithium5")) return Result.success("ML-DSA-87");

        } else if (algoUpper.startsWith("SPHINCS")) {
            if (specStr.contains("sha2-128s")) return Result.success("SLH-DSA-SHA2-128s");
            if (specStr.contains("sha2-128f")) return Result.success("SLH-DSA-SHA2-128f");
            if (specStr.contains("sha2-192s")) return Result.success("SLH-DSA-SHA2-192s");
            if (specStr.contains("sha2-192f")) return Result.success("SLH-DSA-SHA2-192f");
            if (specStr.contains("sha2-256s")) return Result.success("SLH-DSA-SHA2-256s");
            if (specStr.contains("sha2-256f")) return Result.success("SLH-DSA-SHA2-256f");
            if (specStr.contains("shake-128s")) return Result.success("SLH-DSA-SHAKE-128s");
            if (specStr.contains("shake-128f")) return Result.success("SLH-DSA-SHAKE-128f");
            if (specStr.contains("shake-192s")) return Result.success("SLH-DSA-SHAKE-192s");
            if (specStr.contains("shake-192f")) return Result.success("SLH-DSA-SHAKE-192f");
            if (specStr.contains("shake-256s")) return Result.success("SLH-DSA-SHAKE-256s");
            if (specStr.contains("shake-256f")) return Result.success("SLH-DSA-SHAKE-256f");
        }

        return Result.failure(
                "Invalid PQC configuration for algorithm '%s' and spec '%s'."
                        .formatted(algorithm, specStr)
        );
    }
}
