package com.example.demo1.config;

import com.example.demo1.authorization.DeviceClientAuthenticationConverter;
import com.example.demo1.authorization.DeviceClientAuthenticationProvider;
import com.example.demo1.authorization.UserPasswordAuthenticationConverter;
import com.example.demo1.authorization.UserPasswordAuthenticationProvider;
import com.example.demo1.authorization.UserGrantedAuthoritiesConverter;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

/**
 * 认证配置
 * {@link EnableMethodSecurity} 开启全局方法认证，启用JSR250注解支持，启用注解 {@link Secured} 支持，
 * 在Spring Security 6.0版本中将@Configuration注解从@EnableWebSecurity, @EnableMethodSecurity, @EnableGlobalMethodSecurity
 * 和 @EnableGlobalAuthentication 中移除，使用这些注解需手动添加 @Configuration 注解
 * {@link EnableWebSecurity} 注解有两个作用:
 * 1. 加载了WebSecurityConfiguration配置类, 配置安全认证策略。
 * 2. 加载了AuthenticationConfiguration, 配置了认证信息。
 *
 * @author vains
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(jsr250Enabled = true, securedEnabled = true)
public class AutoConfig {

  private static final String CUSTOM_CONSENT_PAGE_URI = "/oauth2/consent";

  private final String secret = "a6bf3454ee08594cc9ebc175db71fd97b0cf27ee";

  /**
   * 配置端点的过滤器链
   *
   * @param http spring security核心配置类
   * @return 过滤器链
   * @throws Exception 抛出
   */
  @Bean
  public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
      RegisteredClientRepository registeredClientRepository,
      AuthorizationServerSettings authorizationServerSettings) throws Exception {
    // 配置默认的设置，忽略认证端点的csrf校验
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

    // 新建设备码converter和provider
    DeviceClientAuthenticationConverter deviceClientAuthenticationConverter =
        new DeviceClientAuthenticationConverter(
            authorizationServerSettings.getDeviceAuthorizationEndpoint());
    DeviceClientAuthenticationProvider deviceClientAuthenticationProvider =
        new DeviceClientAuthenticationProvider(registeredClientRepository);

    http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
        // 开启OpenID Connect 1.0协议相关端点
        .oidc(Customizer.withDefaults())
        // 设置自定义用户确认授权页
        .authorizationEndpoint(
            authorizationEndpoint -> authorizationEndpoint.consentPage(CUSTOM_CONSENT_PAGE_URI))
        // 设置设备码用户验证url(自定义用户验证页)
        .deviceAuthorizationEndpoint(deviceAuthorizationEndpoint ->
            deviceAuthorizationEndpoint.verificationUri("/activate")
        )
        // 设置验证设备码用户确认页面
        .deviceVerificationEndpoint(deviceVerificationEndpoint ->
            deviceVerificationEndpoint.consentPage(CUSTOM_CONSENT_PAGE_URI)
        )
        .clientAuthentication(clientAuthentication ->
            // 客户端认证添加设备码的converter和provider
            clientAuthentication
                .authenticationConverter(deviceClientAuthenticationConverter)
                .authenticationProvider(deviceClientAuthenticationProvider)
        );
    http
        // 当未登录时访问认证端点时重定向至login页面
        .exceptionHandling(exceptions -> exceptions
            .defaultAuthenticationEntryPointFor(
                new LoginUrlAuthenticationEntryPoint("/login"),
                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
            )
        )
        // 处理使用access token访问用户信息端点和客户端注册端点
        .oauth2ResourceServer(resourceServer -> resourceServer
            .jwt(Customizer.withDefaults()));

    // 自定义用户密码认证登录转换器
    UserPasswordAuthenticationConverter converter = new UserPasswordAuthenticationConverter();
    // 自定义用户密码认证登录认证提供
    UserPasswordAuthenticationProvider provider = new UserPasswordAuthenticationProvider();
    http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
        // 让认证服务器元数据中有自定义的认证方式
        .authorizationServerMetadataEndpoint(
            metadata -> metadata.authorizationServerMetadataCustomizer(
                customizer -> customizer.grantType(SecurityConstants.GRANT_TYPE_USER_CODE)))
        // 添加自定义grant_type——用户密码认证登录
        .tokenEndpoint(tokenEndpoint -> tokenEndpoint
            .accessTokenRequestConverter(converter)
            .authenticationProvider(provider));

    DefaultSecurityFilterChain build = http.build();

    // 从框架中获取provider中所需的bean
    OAuth2TokenGenerator<?> tokenGenerator = http.getSharedObject(OAuth2TokenGenerator.class);
    AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
    OAuth2AuthorizationService authorizationService = http.getSharedObject(
        OAuth2AuthorizationService.class);
    // 以上三个bean在build()方法之后调用是因为调用build方法时框架会尝试获取这些类，
    // 如果获取不到则初始化一个实例放入SharedObject中，所以要在build方法调用之后获取
    // 在通过set方法设置进provider中，但是如果在build方法之后调用authenticationProvider(provider)
    // 框架会提示unsupported_grant_type，因为已经初始化完了，在添加就不会生效了
    provider.setTokenGenerator(tokenGenerator);
    provider.setAuthorizationService(authorizationService);
    provider.setAuthenticationManager(authenticationManager);

    return build;
  }

  /**
   * 配置认证相关的过滤器链
   *
   * @param http spring security核心配置类
   * @return 过滤器链
   * @throws Exception 抛出
   */
  @Bean
  public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(authorize -> authorize
            // 放行静态资源
            .requestMatchers("/assets/**", "/webjars/**", "/login").permitAll()
            .anyRequest().authenticated()
        )
        // 指定登录页面
        .formLogin(formLogin ->
            formLogin.loginPage("/login")
        );
    // 添加BearerTokenAuthenticationFilter，将认证服务当做一个资源服务，解析请求头中的token
    http.oauth2ResourceServer(resourceServer -> resourceServer
        .jwt(Customizer.withDefaults()));

    return http.build();
  }

  /**
   * 配置密码解析器，使用BCrypt的方式对密码进行加密和验证
   *
   * @return BCryptPasswordEncoder
   */
  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  /**
   * 自定义jwt，指定jwt加密方式为HS256（平台使用HS512，但是不支持有报错。） 在payload中存放username，实现类似平台效果 {@link
   * UserGrantedAuthoritiesConverter}
   *
   * @return OAuth2TokenCustomizer的实例
   */
  @Bean
  public OAuth2TokenCustomizer<JwtEncodingContext> oAuth2TokenCustomizer() {
    return context -> {
      context.getJwsHeader().algorithm(MacAlgorithm.HS256);

      // 检查登录用户信息是不是UserDetails，排除掉没有用户参与的流程
      if (context.getPrincipal().getPrincipal() instanceof UserDetails user) {
        JwtClaimsSet.Builder claims = context.getClaims();
        // 将用户名放入payload中
        claims.claim("username", user.getUsername());
      }
    };
  }

  /**
   * 自定义jwt解析器，实现从payload中获取username再查询数据库逻辑
   *
   * @return jwt解析器 JwtAuthenticationConverter
   */
  @Bean
  public JwtAuthenticationConverter jwtAuthenticationConverter(
      UserDetailsService userService) {
    UserGrantedAuthoritiesConverter userGrantedAuthoritiesConverter = new UserGrantedAuthoritiesConverter(
        userService);

    JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
    jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(userGrantedAuthoritiesConverter);
    return jwtAuthenticationConverter;
  }

  /**
   * 配置客户端Repository
   *
   * @param jdbcTemplate    db 数据源信息
   * @param passwordEncoder 密码解析器
   * @return 基于数据库的repository
   */
  @Bean
  public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate,
      PasswordEncoder passwordEncoder) {
    // 基于db存储客户端，还有一个基于内存的实现 InMemoryRegisteredClientRepository
    JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(
        jdbcTemplate);

    // 授权码模式
    RegisteredClient registeredClient = RegisteredClient.withId("client-1")
        // 客户端id
        .clientId("messaging-client")
        // 客户端秘钥，使用密码解析器加密
        .clientSecret(passwordEncoder.encode("123456"))
        // 客户端认证方式，基于请求头的认证
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        // 配置资源服务器使用该客户端获取授权时支持的方式
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
        // 授权码模式回调地址，oauth2.1已改为精准匹配，不能只设置域名，并且屏蔽了localhost，本机使用127.0.0.1访问
        .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
        .redirectUri("https://www.baidu.com")
        // 该客户端的授权范围，OPENID与PROFILE是IdToken的scope，获取授权时请求OPENID的scope时认证服务会返回IdToken
        .scope(OidcScopes.OPENID)
        .scope(OidcScopes.PROFILE)
        // 自定义scope
        .scope("message.read")
        .scope("message.write")
        // 客户端设置，设置用户需要确认授权
        .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
        .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofDays(2)).build())
        .build();

    // 持久化客户端
    registeredClientRepository.save(registeredClient);

    // 用户密码模式
    RegisteredClient smsRegisteredClient = RegisteredClient.withId("client-2")
        // 客户端id
        .clientId("user-client")
        // 客户端秘钥，使用密码解析器加密
        .clientSecret(passwordEncoder.encode("123456"))
        // 客户端认证方式，基于请求头的认证
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        // 配置资源服务器使用该客户端获取授权时支持的方式
        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
        .authorizationGrantType(new AuthorizationGrantType(SecurityConstants.GRANT_TYPE_USER_CODE))
        // 该客户端的授权范围，OPENID与PROFILE是IdToken的scope，获取授权时请求OPENID的scope时认证服务会返回IdToken
        .scope(OidcScopes.OPENID)
        .scope(OidcScopes.PROFILE)
        .scope("test01")
        .scope("test02")
        .scope("app")
        // 客户端设置，设置用户需要确认授权
        .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofDays(2)).build())
        .build();

    registeredClientRepository.save(smsRegisteredClient);

    // 设备码授权客户端
    RegisteredClient deviceClient = RegisteredClient.withId("client-3")
        .clientId("device-message-client")
        // 公共客户端
        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
        // 设备码授权
        .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
        // 自定scope
        .scope("message.read")
        .scope("message.write")
        .build();

    registeredClientRepository.save(deviceClient);

    // 客户端模式
    RegisteredClient tokenClient = RegisteredClient.withId("client-4")
        .clientId("token-client")
        .clientSecret(passwordEncoder.encode("123456"))
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
        .scope("app")
        .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
        .build();

    registeredClientRepository.save(tokenClient);

    return registeredClientRepository;
  }

  /**
   * 配置基于db的oauth2的授权管理服务
   *
   * @param jdbcTemplate               db数据源信息
   * @param registeredClientRepository 上边注入的客户端repository
   * @return JdbcOAuth2AuthorizationService
   */
  @Bean
  public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate,
      RegisteredClientRepository registeredClientRepository) {
    // 基于db的oauth2认证服务，还有一个基于内存的服务实现InMemoryOAuth2AuthorizationService
    return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
  }

  /**
   * 配置基于db的授权确认管理服务
   *
   * @param jdbcTemplate               db数据源信息
   * @param registeredClientRepository 客户端repository
   * @return JdbcOAuth2AuthorizationConsentService
   */
  @Bean
  public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate,
      RegisteredClientRepository registeredClientRepository) {
    // 基于db的授权确认管理服务，还有一个基于内存的服务实现InMemoryOAuth2AuthorizationConsentService
    return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
  }

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

  /**
   * 添加认证服务器配置，设置jwt签发者、默认端点请求地址等
   *
   * @return AuthorizationServerSettings
   */
  @Bean
  public AuthorizationServerSettings authorizationServerSettings() {
//    与资源服务器，客户端服务配合使用时需要配置toke中iss为资源服务器地址。
//    return AuthorizationServerSettings.builder().issuer("http://auth-server:8080").build();
    return AuthorizationServerSettings.builder().build();
  }

  @Bean
  public UserDetailsService users(PasswordEncoder passwordEncoder) {
    UserDetails user = User.withUsername("admin")
        .password(passwordEncoder.encode("123456"))
        .roles("admin", "normal", "unAuthentication")
        .authorities("app", "web", "/test2", "/test3")
        .build();
    return new InMemoryUserDetailsManager(user);
  }
}
