package com.example.demo1resource.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;

@Configuration
public class AutoConfig {

  private final String secret = "a6bf3454ee08594cc9ebc175db71fd97b0cf27ee";

  /**
   * 配置jwk源，使用非对称加密，公开用于检索匹配指定选择器的JWK的方法
   *
   * @return JWKSource
   */
  @Bean
  public JWKSource<SecurityContext> jwkSource() {
    ArrayList<JWK> jwks = new ArrayList<>();

    byte[] bytes = secret.getBytes(StandardCharsets.UTF_8);
    OctetSequenceKey octetKey = new OctetSequenceKey.Builder(bytes)
        .algorithm(JWSAlgorithm.HS256)
        .build();
    jwks.add(octetKey);

    return new ImmutableJWKSet<>(new JWKSet(jwks));

  }

  /**
   * 配置jwt解析器
   *
   * @param jwkSource 授权令牌时用到的加密方式
   * @return JwtDecoder
   */
  @Bean
  public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
  }

}
