package com.arplanets.auth.repository;

import com.arplanets.auth.model.po.domain.AuthActivity;

public interface AuthActivityRepository {

    void save(AuthActivity authActivity);
}
