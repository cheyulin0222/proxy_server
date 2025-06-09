package com.arplanets.auth.component.spring.oidc;

import com.arplanets.auth.repository.persistence.RegisteredClientPersistentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

/**
 * Spring 用來操作 oauth2_registered_client
 */
@Component
@RequiredArgsConstructor
public class RegisteredClientRepositoryImpl implements RegisteredClientRepository {

    private final RegisteredClientPersistentRepository registeredClientPersistentRepository;

    @Override
    public void save(RegisteredClient registeredClient) {
        registeredClientPersistentRepository.save(registeredClient);
    }

    @Nullable
    @Override
    public RegisteredClient findById(String id) {
        return registeredClientPersistentRepository.findById(id);
    }

    @Nullable
    @Override
    public RegisteredClient findByClientId(String clientId) {
        return registeredClientPersistentRepository.findByClientId(clientId);
    }
}
