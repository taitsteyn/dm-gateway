package com.dataq.gateway.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.security.Principal;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtTokenService {

    private static final Logger LOG = LoggerFactory.getLogger(JwtTokenService.class);

    private static final String ISSUER = "DataQ";
    private static final String EXECUTION_ID = "executionId";
    private static final String EMAIL = "email";
    private static final String GROUPS = "groups";
    private static final String ROLES = "roles";

    private final Key secretKey;

    public JwtTokenService(@Value("${jwt.secret.key}") String secretKeyValue) {
        secretKey = decodeKey(secretKeyValue);
    }

    public String generateDmsToken(Principal originalPrincipal) {
        if (originalPrincipal instanceof OAuth2AuthenticationToken oAuth2AuthenticationToken) {
            DefaultOidcUser oidcUser = (DefaultOidcUser) oAuth2AuthenticationToken.getPrincipal();
            String userId = oidcUser.getPreferredUsername();
            Instant issuedAt = oidcUser.getIssuedAt();
            Instant expiresAt = oidcUser.getExpiresAt();
            Map<String, Object> claims = oidcUser.getClaims();
            return generateToken(userId, issuedAt, expiresAt, claims);
        }
        throw new RuntimeException("Unable to generate DMS token form original principal");
    }

    private String generateToken(String userId, Instant issuedAt, Instant expiresAt, Map<String, Object> claimsParam) {
        try {
            if (userId == null) {
                throw new RuntimeException("UserId is required to create token");
            }
            Map<String, Object> claims = new HashMap<>();
            claims.put(Claims.ISSUER, ISSUER);
            claims.put(Claims.SUBJECT, userId);
            claims.putAll(claimsParam);
            String token = Jwts.builder()
                    .setClaims(claims)
                    .setIssuedAt(Date.from(issuedAt))
                    .setExpiration(Date.from(expiresAt))
                    .signWith(secretKey)
                    .compact();
            LOG.debug("The token was generated for userId: {}, token: {}", userId, token);
            return token;
        } catch (JwtException ex) {
            String message = "Unable to generate jwt token";
            LOG.error(message, ex);
            throw new RuntimeException(message, ex);
        }
    }

    private static Key decodeKey(String secretKeyValue) {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKeyValue));
    }
}
