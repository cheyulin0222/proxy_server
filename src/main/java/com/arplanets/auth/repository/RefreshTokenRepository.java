package com.arplanets.auth.repository;


import com.arplanets.auth.model.po.domain.RefreshToken;

public interface RefreshTokenRepository {

    void save(RefreshToken refreshToken);
}
