package com.example.demo.security;


import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RateLimitingFilter extends OncePerRequestFilter {

    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    private Bucket createNewBucket(){
        //It allows ten requests per minute to protected routes
        Bandwidth limit = Bandwidth.classic(10, Refill.greedy(10, Duration.ofMinutes(1)));
        return Bucket.builder().addLimit(limit).build();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();

        //logic to apply rate limit only in critical auth routes
        if(path.startsWith("/api/auth/login") || path.startsWith("api/auth/reset-password")) {

            String clientIp = getClientIP(request);
            Bucket bucket = buckets.computeIfAbsent(clientIp, k -> createNewBucket());

            if(!bucket.tryConsume(1)){
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.setContentType("application/json");
                response.getWriter().write("\"{\\\"error\\\": \\\"too many requests. try again in one minute.\\\"}\"");
                return;
            }
        }
        filterChain.doFilter(request, response);

    }

    private String getClientIP(HttpServletRequest request){

        String xfHeader = request.getHeader("X-Forwarded-For");
        if(xfHeader == null || xfHeader.isEmpty()){
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }
}
