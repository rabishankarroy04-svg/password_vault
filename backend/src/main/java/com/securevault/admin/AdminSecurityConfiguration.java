package com.securevault.admin;

import com.securevault.common.SecurityEventRecorder;
import java.util.Arrays;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class AdminSecurityConfiguration {
    @Bean
    AdminSessionAuthenticationFilter adminSessionAuthenticationFilter(JdbcTemplate jdbcTemplate,
            SecurityEventRecorder eventRecorder,
            @Value("${security.jwt.secret-base64}") String secretBase64) {
        return new AdminSessionAuthenticationFilter(jdbcTemplate, secretBase64, eventRecorder);
    }

    @Bean
    FilterRegistrationBean<AdminSessionAuthenticationFilter> disableServletFilterRegistration(
            AdminSessionAuthenticationFilter adminFilter) {
        FilterRegistrationBean<AdminSessionAuthenticationFilter> registration = new FilterRegistrationBean<>(adminFilter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource(
            @Value("${security.cors.allowed-origins:http://localhost:3000,http://127.0.0.1:3000,http://localhost:4300,http://127.0.0.1:4300}") String allowedOrigins) {
        CorsConfiguration configuration = new CorsConfiguration();
        List<String> patterns = new java.util.ArrayList<>(Arrays.stream(allowedOrigins.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList());
        if (!patterns.contains("https://*.onrender.com")) {
            patterns.add("https://*.onrender.com");
        }
        if (!patterns.contains("http://localhost:*")) {
            patterns.add("http://localhost:*");
        }
        if (!patterns.contains("http://127.0.0.1:*")) {
            patterns.add("http://127.0.0.1:*");
        }
        configuration.setAllowedOriginPatterns(patterns);
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-SecureVault-Device", "X-Forwarded-For"));
        configuration.setExposedHeaders(List.of("Authorization", "Cache-Control"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    SecurityFilterChain secureVaultSecurityFilterChain(HttpSecurity http,
            AdminSessionAuthenticationFilter adminFilter,
            CorsConfigurationSource corsConfigurationSource) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .anyRequest().permitAll())
                .exceptionHandling(errors -> errors
                        .authenticationEntryPoint((request, response, exception) -> {
                            response.setStatus(401);
                            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                            response.getWriter().write("{\"code\":\"UNAUTHENTICATED\",\"message\":\"Sign in with an administrator account to continue.\"}");
                        })
                        .accessDeniedHandler((request, response, exception) -> {
                            response.setStatus(403);
                            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                            response.getWriter().write("{\"code\":\"ADMIN_REQUIRED\",\"message\":\"This dashboard is available only to administrator accounts.\"}");
                        }))
                .addFilterBefore(adminFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}
