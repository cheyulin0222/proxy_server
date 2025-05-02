package com.arplanets.auth.service;

import com.arplanets.auth.model.po.domain.User;


public interface UserService {

    User findOrCreateUser(String providerName, String sub);

}
