package com.arplanets.auth.repository.persistence;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

public interface RegisteredClientPersistentRepository {

    void save(RegisteredClient registeredClient);
    RegisteredClient findById(String id);
    RegisteredClient findByClientId(String clientId);
    String findUserPoolIdByClientId(String clientId);

}
