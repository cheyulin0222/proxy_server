package com.arplanets.auth.service.impl;

import com.arplanets.auth.model.po.domain.User;
import com.arplanets.auth.repository.UserRepository;
import com.arplanets.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Transactional
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Override
    public User findOrCreateUser(String providerName, String sub) {
        String uid = generateUid(providerName, sub);
        Optional<User> option = userRepository.findById(uid);

        if (option.isEmpty()) {
            User user = User.builder()
                .userId(uid)
                .build();

            return userRepository.insert(user);

        }

        return option.get();

    }

    private String generateUid(String providerName, String sub) {
        return providerName + ":" + sub;
    }
}
