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
public class AuthActivity {

    private String authSessionId;

    private String refreshTokenValue;

    private String accessTokenValue;

    private String userId;

    private String action;

    private String ip;

    private String deviceType;

    private String osName;

    private String osVersion;

    private Instant createdAt;

}
