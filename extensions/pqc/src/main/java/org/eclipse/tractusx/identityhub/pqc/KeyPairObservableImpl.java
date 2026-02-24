package org.eclipse.tractusx.identityhub.pqc;

import org.eclipse.edc.identityhub.spi.keypair.events.KeyPairEventListener;
import org.eclipse.edc.identityhub.spi.keypair.events.KeyPairObservable;
import org.eclipse.edc.spi.observe.ObservableImpl;

public class KeyPairObservableImpl extends ObservableImpl<KeyPairEventListener> implements KeyPairObservable {
}
