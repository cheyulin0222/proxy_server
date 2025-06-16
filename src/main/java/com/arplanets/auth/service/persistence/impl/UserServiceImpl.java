package com.arplanets.auth.service.persistence.impl;

import com.arplanets.auth.model.po.domain.User;
import com.arplanets.auth.repository.persistence.UserRepository;
import com.arplanets.auth.service.persistence.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

@Transactional
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final ClientRegistrationRepository clientRegistrationRepository;

    @Override
    public User findOrCreateUser(String registrationId, String idpSub) {

        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(registrationId);

        if (clientRegistration == null) {
            throw new IllegalArgumentException("Cannot find ClientRegistration by registrationId :" + registrationId);
        }

        String providerName = clientRegistration.getClientName();
        String uuid = providerName + "_" + idpSub;

        Optional<User> option = userRepository.findByRegistrationIdAndUuid(registrationId, uuid);

        if (option.isEmpty()) {
            User user = User.builder()
                    .userId(UUID.randomUUID().toString())
                    .registrationId(registrationId)
                    .uuid(uuid)
                    .build();

            return userRepository.insert(user);
        }

        return option.get();








    }

}
