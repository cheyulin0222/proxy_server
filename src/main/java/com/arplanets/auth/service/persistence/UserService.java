package com.arplanets.auth.service.persistence;

import com.arplanets.auth.model.po.domain.User;


public interface UserService {

    User findOrCreateUser(String registrationId, String idpSub);

}
