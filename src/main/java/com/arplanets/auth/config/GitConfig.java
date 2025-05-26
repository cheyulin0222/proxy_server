package com.arplanets.auth.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

/**
 * 讀取 git.properties
 * 將屬性載入 Spring Environment
 */
@Configuration
@PropertySource("classpath:git.properties")
public class GitConfig {
}
