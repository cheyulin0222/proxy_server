package com.arplanets.auth.test;


import com.arplanets.auth.model.po.domain.RefreshToken;

public interface RefreshTokenRepository {

    void save(RefreshToken refreshToken);
}
