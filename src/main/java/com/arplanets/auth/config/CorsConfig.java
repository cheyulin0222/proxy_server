package com.arplanets.auth.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**") // 允許對所有路徑應用 CORS
//                .allowedOrigins()
                .allowedOriginPatterns("http://localhost:*")
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS") // 允許所有常用 HTTP 方法
                .allowedHeaders("*") // 允許所有 Header
                .allowCredentials(true) // 允許攜帶憑證 (cookies, HTTP authentication)
                .maxAge(3600); // 預檢請求的有效時間 (秒)
    }


}
