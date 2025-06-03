package com.arplanets.auth.repository;

import com.arplanets.auth.model.po.domain.UserPool;

import java.util.List;

public interface UserPoolRepository {

    List<UserPool> findAll();
}
