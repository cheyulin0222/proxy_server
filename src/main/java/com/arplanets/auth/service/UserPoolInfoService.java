package com.arplanets.auth.service;

import com.arplanets.auth.model.UserPoolInfo;
import com.arplanets.auth.model.po.domain.UserPool;

public interface UserPoolInfoService {

    void registerUserPoolInfo(UserPool userPool) throws Exception;
    UserPoolInfo findByPoolId(String poolId);
    UserPoolInfo findByPoolName(String poolName);


}
