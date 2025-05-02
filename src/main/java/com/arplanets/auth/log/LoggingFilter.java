package com.arplanets.auth.log;

import com.arplanets.auth.model.RequestContext;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
@Slf4j
public class LoggingFilter extends OncePerRequestFilter {

    private final LogContext logContext;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
            // 產生 request_id
            String requestId = logContext.generateId("request");

            // 產生 requestContext
            RequestContext requestContext = RequestContext.builder()
                    .requestId(requestId)
                    .build();

            // 將 requestContext 存到 HttpServletRequest
            request.setAttribute("requestContext", requestContext);

            filterChain.doFilter(request, response);

    }
}
