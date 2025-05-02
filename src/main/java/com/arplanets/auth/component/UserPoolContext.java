package com.arplanets.auth.component;

import com.arplanets.auth.model.po.domain.UserPool;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class UserPoolContext {

    private final String userPoolId;
    private final UserPool userPool;

    public String getPoolName() {
        return userPool.getPoolName();
    }
}
