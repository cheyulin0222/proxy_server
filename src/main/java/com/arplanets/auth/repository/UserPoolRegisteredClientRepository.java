package com.arplanets.auth.repository;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

public class UserPoolRegisteredClientRepository {
    public RegisteredClient findByClientIdAndUserPoolId(String clientId, String userPoolId) {
        return null;
    }
}
