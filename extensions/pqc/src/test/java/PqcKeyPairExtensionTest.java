import org.eclipse.edc.identityhub.spi.keypair.store.KeyPairResourceStore;
import org.eclipse.edc.identityhub.spi.participantcontext.store.ParticipantContextStore;
import org.eclipse.edc.junit.extensions.DependencyInjectionExtension;
import org.eclipse.edc.spi.monitor.Monitor;
import org.eclipse.edc.spi.security.Vault;
import org.eclipse.edc.spi.system.ServiceExtensionContext;
import org.eclipse.edc.transaction.spi.TransactionContext;
import org.eclipse.tractusx.identityhub.pqc.KeyPairServiceImpl;
import org.eclipse.tractusx.identityhub.pqc.PqcKeyPairExtension;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


@ExtendWith(DependencyInjectionExtension.class)
class PqcKeyPairExtensionTest {

    private final Monitor monitor = mock(Monitor.class);
    private final Vault vault = mock(Vault.class);
    private final KeyPairResourceStore keyPairResourceStore = mock(KeyPairResourceStore.class);
    private final ParticipantContextStore participantContextStore = mock(ParticipantContextStore.class);
    private final TransactionContext transactionContext = mock(TransactionContext.class);

    @BeforeEach
    void setUp(ServiceExtensionContext context) {
        context.registerService(Vault.class, vault);
        context.registerService(KeyPairResourceStore.class, keyPairResourceStore);
        context.registerService(ParticipantContextStore.class, participantContextStore);
        context.registerService(TransactionContext.class, transactionContext);

        when(context.getMonitor()).thenReturn(monitor);
        when(monitor.withPrefix(anyString())).thenReturn(monitor);

    }

    @Test
    void initialize_shouldRegisterBcPqcProvider(PqcKeyPairExtension extension, ServiceExtensionContext context) {
        extension.initialize(context);

        var provider = java.security.Security.getProvider("BCPQC");
        assertThat(provider).isNotNull();
    }

    @Test
    void createKeyPairService_shouldReturnValidService(PqcKeyPairExtension extension, ServiceExtensionContext context) {
        extension.initialize(context);

        var service = extension.createKeyPairService(context);

        assertThat(service).isNotNull();
        assertThat(service).isInstanceOf(KeyPairServiceImpl.class);
    }
}
