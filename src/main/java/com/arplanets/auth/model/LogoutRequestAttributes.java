package com.arplanets.auth.model;

import lombok.*;
import org.springframework.util.Assert;

import java.time.Instant;

@Data
public class LogoutRequestAttributes {

    private String clientFinalRedirectUri;
    private Instant expiryTime;

    public LogoutRequestAttributes(String clientFinalRedirectUri, long expiresInSeconds) {
        Assert.hasText(clientFinalRedirectUri, "clientFinalRedirectUri cannot be empty");
        this.clientFinalRedirectUri = clientFinalRedirectUri;
        // 設定過期時間
        this.expiryTime = Instant.now().plusSeconds(expiresInSeconds);
    }

    public boolean isExpired() {
        return Instant.now().isAfter(expiryTime);
    }
}
