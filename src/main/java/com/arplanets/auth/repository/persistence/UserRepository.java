package com.arplanets.auth.repository.persistence;

import com.arplanets.auth.model.po.domain.User;

import java.util.Optional;

public interface UserRepository {

    Optional<User> findById(String uid);

    Optional<User> findByRegistrationIdAndUuid(String registrationId, String uuid);

    User insert(User user);

}
