package com.arplanets.auth.model;

import com.arplanets.auth.model.po.domain.AccessToken;
import com.arplanets.auth.model.po.domain.RefreshToken;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class TokenInfo {

    private AccessToken accessToken;
    private RefreshToken refreshToken;
}
