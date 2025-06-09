package com.arplanets.auth.service.persistence;

import java.util.Map;

public interface UserInfoService {

    void saveUserClaims(String uid, String providerName, Map<String, Object> userInfo);
}
