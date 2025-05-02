package com.arplanets.auth.repository;

import com.arplanets.auth.model.po.domain.UserPool;

import java.util.List;

public interface UserPoolRepository {

    UserPool findById(String userPoolId);
    UserPool findByPoolName(String poolName);
    List<UserPool> findAll();
    UserPool save(UserPool userPool);
}
