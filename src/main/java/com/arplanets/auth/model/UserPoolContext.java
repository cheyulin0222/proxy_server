package com.arplanets.auth.model;

import lombok.Builder;

@Builder
public record UserPoolContext(String userPoolId, UserPoolInfo userPoolInfo) {
}
