package com.dataq.gateway.config.filter;

import com.dataq.gateway.service.JwtTokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.web.server.ServerWebExchange;

public class DmsTokenRelayGatewayFilterFactory extends AbstractGatewayFilterFactory<DmsTokenRelayGatewayFilterFactory.Config> {

    private static final Logger LOG = LoggerFactory.getLogger(DmsTokenRelayGatewayFilterFactory.class);

    private final JwtTokenService jwtTokenService;

    public DmsTokenRelayGatewayFilterFactory(JwtTokenService jwtTokenService) {
        super(Config.class);
        this.jwtTokenService = jwtTokenService;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            LOG.debug("DmsTokenRelayGatewayFilter applied");
            return exchange.getPrincipal()
                    .map(jwtTokenService::generateDmsToken)
                    .map(token -> withBearerAuth(exchange, token))
                    .defaultIfEmpty(exchange).flatMap(chain::filter);
        };
    }

    private ServerWebExchange withBearerAuth(ServerWebExchange exchange, String token) {
        return exchange.mutate()
                .request(r -> r.headers(headers -> headers.setBearerAuth(token)))
                .build();
    }
    
    public static class Config {

    }

}
