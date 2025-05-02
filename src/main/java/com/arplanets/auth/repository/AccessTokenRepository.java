package com.arplanets.auth.repository;

import com.arplanets.auth.model.po.domain.AccessToken;

public interface AccessTokenRepository {
    void save(AccessToken accessToken);
}
