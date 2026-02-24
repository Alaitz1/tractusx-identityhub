
import org.eclipse.tractusx.identityhub.pqc.HybridKeyPair;
import org.junit.jupiter.api.Test;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import static org.assertj.core.api.Assertions.assertThat;

class HybridKeyPairTest {

    @Test
    void shouldVerifyEquality() throws NoSuchAlgorithmException {
        var kpg = KeyPairGenerator.getInstance("Ed25519");
        var kp1 = kpg.generateKeyPair();
        var kp2 = kpg.generateKeyPair();

        var hybrid1 = new HybridKeyPair(kp1, kp2);
        var hybrid2 = new HybridKeyPair(kp1, kp2);
        var hybrid3 = new HybridKeyPair(kp2, kp1);

        assertThat(hybrid1).isEqualTo(hybrid2);
        assertThat(hybrid1.hashCode()).isEqualTo(hybrid2.hashCode());
        assertThat(hybrid1).isNotEqualTo(hybrid3);
    }
}