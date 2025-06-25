package com.arplanets.auth.test;

import com.arplanets.auth.model.po.domain.AccessToken;

public interface AccessTokenRepository {
    void save(AccessToken accessToken);
}
