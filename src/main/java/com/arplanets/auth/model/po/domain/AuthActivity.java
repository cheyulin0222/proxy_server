package com.arplanets.auth.model.po.domain;

import com.fasterxml.jackson.annotation.JsonFormat;
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

    private String authId;

    private String refreshTokenValue;

    private String accessTokenValue;

    private String userId;

    private String action;

    private String ip;

    private String deviceType;

    private String osName;

    private String osVersion;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSXXX", timezone = "Asia/Taipei")
    private Instant createdAt;

}
