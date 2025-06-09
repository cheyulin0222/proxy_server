package com.arplanets.auth.repository.persistence;


import com.arplanets.auth.model.po.domain.RefreshToken;

public interface RefreshTokenRepository {

    void save(RefreshToken refreshToken);
}
