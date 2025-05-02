package com.arplanets.auth.model.po.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AccessToken {

    private String accessTokenValue;

    private String userId;

    private String clientId;

    private Instant createdAt;

    private Instant expiresAt;

    private String authSessionId;

    private String refreshTokenValue;


}
