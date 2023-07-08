package com.dataq.gateway.config;

import com.dataq.gateway.config.filter.DmsTokenRelayGatewayFilterFactory;
import com.dataq.gateway.service.JwtTokenService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf().disable()
                .authorizeExchange().anyExchange()
                .authenticated()
                .and().oauth2Login().and()
                .oauth2ResourceServer().jwt().and()
                .and().build();
    }

    @Bean
    public DmsTokenRelayGatewayFilterFactory dmsTokenRelayGatewayFilterFactory(JwtTokenService jwtTokenService) {
        return new DmsTokenRelayGatewayFilterFactory(jwtTokenService);
    }
}