package com.arplanets.auth.service.inmemory;

import com.arplanets.auth.model.UserPoolInfo;

public interface UserPoolInfoSource {
    UserPoolInfo getUserPoolInfo();
}
