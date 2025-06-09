package com.arplanets.auth.repository.persistence;

import com.arplanets.auth.model.po.domain.UserPool;

import java.util.List;

public interface UserPoolRepository {

    List<UserPool> findAll();
}
