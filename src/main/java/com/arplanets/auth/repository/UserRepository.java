package com.arplanets.auth.repository;

import com.arplanets.auth.model.po.domain.User;

import java.util.Optional;

public interface UserRepository {

    Optional<User> findById(String uid);

    User insert(User user);

    boolean existsById(String uid);
}
