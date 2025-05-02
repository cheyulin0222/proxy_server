package com.arplanets.auth.model.po.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ClaimMapping {

    private String registrationId;

    private String claimName;

    private String idpClaimName;

    private String scope;

    private Boolean isActive;

    private Instant createdAt;

    private Instant updatedAt;

    private Instant deletedAt;
}
