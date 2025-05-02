package com.arplanets.auth.model.po.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.time.Instant;

@Data
@Builder
@AllArgsConstructor
public class ExtendedRegisteredClient {

    private final RegisteredClient registeredClient;
    private final Boolean isActive;
    private final Instant updatedAt;
    private final Instant deletedAt;

}
