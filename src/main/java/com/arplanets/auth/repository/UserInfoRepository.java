package com.arplanets.auth.repository;

import com.arplanets.auth.model.po.domain.UserClaim;

import java.util.List;

public interface UserInfoRepository {

    void saveAll(List<UserClaim> claims);
    List<UserClaim> findByUserId(String userId);

}
