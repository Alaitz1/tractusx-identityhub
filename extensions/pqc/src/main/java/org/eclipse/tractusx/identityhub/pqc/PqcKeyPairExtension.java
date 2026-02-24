package org.eclipse.tractusx.identityhub.pqc;

import org.eclipse.edc.identityhub.spi.keypair.KeyPairService;
import org.eclipse.edc.identityhub.spi.keypair.events.KeyPairObservable;
import org.eclipse.edc.identityhub.spi.keypair.store.KeyPairResourceStore;
import org.eclipse.edc.identityhub.spi.participantcontext.store.ParticipantContextStore;
import org.eclipse.edc.runtime.metamodel.annotation.Extension;
import org.eclipse.edc.runtime.metamodel.annotation.Inject;
import org.eclipse.edc.runtime.metamodel.annotation.Provider;
import org.eclipse.edc.spi.monitor.Monitor;
import org.eclipse.edc.spi.security.Vault;
import org.eclipse.edc.spi.system.ServiceExtension;
import org.eclipse.edc.spi.system.ServiceExtensionContext;
import org.eclipse.edc.transaction.spi.TransactionContext;

import java.security.Security;

@Extension(value = "PQC KeyPair Extension")
public class PqcKeyPairExtension implements ServiceExtension {

    @Inject
    private Vault vault;

    @Inject
    private KeyPairResourceStore keyPairResourceStore;

    @Inject
    private ParticipantContextStore participantContextStore;

    @Inject
    private TransactionContext transactionContext;

    private Monitor monitor;
    private KeyPairService keyPairService;
    private KeyPairObservable observable;

    @Override
    public void initialize(ServiceExtensionContext context) {
        monitor = context.getMonitor().withPrefix("PQC-Extension");

        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider());
            monitor.info("BouncyCastle PQC provider registered.");
        }
    }

    @Provider
    public KeyPairObservable createKeyPairObservable() {
        if (observable == null) {
            observable = new KeyPairObservableImpl();
        }
        return observable;
    }

    @Provider
    public KeyPairService createKeyPairService(ServiceExtensionContext context) {
        if (keyPairService == null) {
            var obs = createKeyPairObservable();

            // Ya no le pasamos la factory porque es estática y el servicio ya no la pide en el constructor
            keyPairService = new KeyPairServiceImpl(
                    keyPairResourceStore,
                    vault,
                    context.getMonitor().withPrefix("PQC-Service"),
                    obs,
                    transactionContext,
                    participantContextStore
            );
        }
        return keyPairService;
    }

    @Override
    public void start() {
        monitor.info("PQC KeyPair Extension started with PQC-aware KeyPairService");
    }
}