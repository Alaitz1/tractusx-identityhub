package org.eclipse.tractusx.identityhub.pqc;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Objects;

public final class HybridKeyPair {

    private final KeyPair classicalKeyPair;
    private final KeyPair pqcKeyPair;

    public HybridKeyPair(KeyPair classical, KeyPair pqc) {

        this.classicalKeyPair = Objects.requireNonNull(classical, "classical keypair must not be null");
        this.pqcKeyPair = Objects.requireNonNull(pqc, "pqc keypair must not be null");
    }

    public KeyPair getClassicalKeyPair() {

        return classicalKeyPair;
    }

    public KeyPair getPqcKeyPair() {
        return pqcKeyPair;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof HybridKeyPair that)) return false;
        return keysEqual(classicalKeyPair, that.classicalKeyPair) && keysEqual(pqcKeyPair, that.pqcKeyPair);
    }

    private static boolean keysEqual(KeyPair a, KeyPair b) {
        return Arrays.equals(a.getPublic().getEncoded(), b.getPublic().getEncoded()) && Arrays.equals(a.getPrivate().getEncoded(), b.getPrivate().getEncoded());
    }

    @Override
    public int hashCode() {
        return Objects.hash(
                Arrays.hashCode(classicalKeyPair.getPublic().getEncoded()),
                Arrays.hashCode(pqcKeyPair.getPublic().getEncoded())
        );
    }

    @Override
    public String toString() {
        return "HybridKeyPair{classical=" + classicalKeyPair.getPublic().getAlgorithm() + ", pqc=" + pqcKeyPair.getPublic().getAlgorithm() + "}";
    }
}
