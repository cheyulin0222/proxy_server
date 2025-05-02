package com.arplanets.auth.model.po.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserPool {

    private String userPoolId;

    private String poolName;

    private Set<String> scopes;

    private String jwkSet;

    private Boolean isActive;

    private Instant createdAt;

    private Instant updatedAt;

    private Instant deletedAt;

}
