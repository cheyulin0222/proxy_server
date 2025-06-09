package com.arplanets.auth.service.persistence.impl;

import com.arplanets.auth.model.po.domain.User;
import com.arplanets.auth.repository.persistence.UserRepository;
import com.arplanets.auth.service.persistence.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

@Transactional
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Override
    public User findOrCreateUser(String registrationId, String idpSub) {
        Optional<User> option = userRepository.findByRegistrationIdAndIdpSub(registrationId, idpSub);

        if (option.isEmpty()) {
            User user = User.builder()
                    .userId(UUID.randomUUID().toString())
                    .registrationId(registrationId)
                    .idpSub(idpSub)
                    .build();

            return userRepository.insert(user);
        }

        return option.get();
    }

}
