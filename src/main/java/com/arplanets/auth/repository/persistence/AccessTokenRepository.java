package com.arplanets.auth.repository.persistence;

import com.arplanets.auth.model.po.domain.AccessToken;

public interface AccessTokenRepository {
    void save(AccessToken accessToken);
}
