package com.arplanets.auth.repository;

import java.util.List;
import java.util.Map;

public interface ClientRegistrationPersistentRepository {

    List<Map<String, Object>> findAll();
}
