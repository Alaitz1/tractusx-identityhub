/*
 *   Copyright (c) 2025 Cofinity-X
 *   Copyright (c) 2025 Contributors to the Eclipse Foundation
 *
 *   See the NOTICE file(s) distributed with this work for additional
 *   information regarding copyright ownership.
 *
 *   This program and the accompanying materials are made available under the
 *   terms of the Apache License, Version 2.0 which is available at
 *   https://www.apache.org/licenses/LICENSE-2.0.
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *   License for the specific language governing permissions and limitations
 *   under the License.
 *
 *   SPDX-License-Identifier: Apache-2.0
 *
 */

package org.eclipse.tractusx.identityhub.seed;

import org.eclipse.edc.identityhub.spi.authentication.ServicePrincipal;
import org.eclipse.edc.identityhub.spi.participantcontext.ParticipantContextService;
import org.eclipse.edc.identityhub.spi.participantcontext.model.KeyDescriptor;
import org.eclipse.edc.identityhub.spi.participantcontext.model.ParticipantManifest;
import org.eclipse.edc.runtime.metamodel.annotation.Inject;
import org.eclipse.edc.runtime.metamodel.annotation.Setting;
import org.eclipse.edc.spi.EdcException;
import org.eclipse.edc.spi.monitor.Monitor;
import org.eclipse.edc.spi.security.Vault;
import org.eclipse.edc.spi.system.ServiceExtension;
import org.eclipse.edc.spi.system.ServiceExtensionContext;

import java.util.List;
import java.util.Map;

import static java.util.Optional.ofNullable;

public class SuperUserSeedExtension implements ServiceExtension {
    public static final String NAME = "SUPER USER Seed Extension";
    public static final String DEFAULT_SUPER_USER_PARTICIPANT_ID = "super-user";

    @Setting(value = "Explicitly set the initial API key for the Super-User")
    public static final String SUPERUSER_APIKEY_PROPERTY = "edc.ih.api.superuser.key";

    @Setting(value = "Config value to set the super-user's participant ID.", defaultValue = DEFAULT_SUPER_USER_PARTICIPANT_ID)
    public static final String SUPERUSER_PARTICIPANT_ID_PROPERTY = "edc.ih.api.superuser.id";
    private String superUserParticipantId;
    private String superUserApiKey;
    private Monitor monitor;
    @Inject
    private ParticipantContextService participantContextService;
    @Inject
    private Vault vault;

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public void initialize(ServiceExtensionContext context) {
        superUserParticipantId = context.getSetting(SUPERUSER_PARTICIPANT_ID_PROPERTY, DEFAULT_SUPER_USER_PARTICIPANT_ID);
        superUserApiKey = context.getSetting(SUPERUSER_APIKEY_PROPERTY, null);
        monitor = context.getMonitor().withPrefix(SuperUserSeedExtension.class.getSimpleName());
    }

    @Override
    public void start() {
        // create super-user
        if (participantContextService.getParticipantContext(superUserParticipantId).succeeded()) { // already exists
            monitor.debug("super-user already exists with ID '%s', will not re-create".formatted(superUserParticipantId));
            return;
        }
        participantContextService.createParticipantContext(ParticipantManifest.Builder.newInstance()
                        .participantId(superUserParticipantId)
                        .did("did:web:%s".formatted(superUserParticipantId)) // doesn't matter, not intended for resolution
                        .active(true)
                        .key(KeyDescriptor.Builder.newInstance()
                                .keyGeneratorParams(Map.of("algorithm", "EdDSA", "curve", "Ed25519"))
                                .keyId("%s-key".formatted(superUserParticipantId))
                                .privateKeyAlias("%s-alias".formatted(superUserParticipantId))
                                .build())
                        .roles(List.of(ServicePrincipal.ROLE_ADMIN))
                        .build())
                .onSuccess(generatedKey -> {
                    var apiKey = ofNullable(superUserApiKey)
                            .map(overrideKey -> {
                                if (!overrideKey.contains(".")) {
                                    monitor.warning("Super-user key override: this key appears to have an invalid format, you may be unable to access some APIs. It must follow the structure: 'base64(<participantId>).<random-string>'");
                                }
                                participantContextService.getParticipantContext(superUserParticipantId)
                                        .onSuccess(pc -> vault.storeSecret(pc.getApiTokenAlias(), overrideKey)
                                                .onSuccess(u -> monitor.debug("Super-user key override successful"))
                                                .onFailure(f -> monitor.warning("Error storing API key in vault: %s".formatted(f.getFailureDetail()))))
                                        .onFailure(f -> monitor.warning("Error overriding API key for '%s': %s".formatted(superUserParticipantId, f.getFailureDetail())));
                                return overrideKey;
                            })
                            .orElse(generatedKey.apiKey());
                    monitor.info("Created user 'super-user'. Please take note of the API Key: %s".formatted(apiKey));
                })
                .orElseThrow(f -> new EdcException("Error creating Super-User: " + f.getFailureDetail()));
    }
}
