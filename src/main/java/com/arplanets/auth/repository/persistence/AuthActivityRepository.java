package com.arplanets.auth.repository.persistence;

import com.arplanets.auth.model.po.domain.AuthActivity;

public interface AuthActivityRepository {

    void save(AuthActivity authActivity);
}
