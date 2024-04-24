package com.example.demo1.authorization;

import java.util.ArrayList;
import java.util.Collection;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.StringUtils;

/**
 * 用于解析token时，从payload获取用户名查询数据库获取权限。
 */
public class UserGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

  private final UserDetailsService userService;

  private String authoritiesClaimDelimiter = " ";

  public UserGrantedAuthoritiesConverter(UserDetailsService userService) {
    this.userService = userService;
  }

  @Override
  public Collection<GrantedAuthority> convert(Jwt jwt) {
    Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
    Object authorities = jwt.getClaim("scope");
    if (authorities instanceof String str && (StringUtils.hasText(str))) {
        String[] split = str.split(this.authoritiesClaimDelimiter);
        for (String auth: split) {
          grantedAuthorities.add(new SimpleGrantedAuthority(auth));
        }
    }

    if (authorities instanceof Collection) {
      for (String str : castAuthoritiesToCollection(authorities)) {
        grantedAuthorities.add(new SimpleGrantedAuthority(str));
      }
    }

    String username = jwt.getClaim("username");
    if (StringUtils.hasText(username)) {
      UserDetails userDetails = userService.loadUserByUsername(username);
      grantedAuthorities.addAll(userDetails.getAuthorities());
    }
    return grantedAuthorities;
  }

  @SuppressWarnings("unchecked")
  private Collection<String> castAuthoritiesToCollection(Object authorities) {
    return (Collection<String>) authorities;
  }

  public void setAuthoritiesClaimDelimiter(String split) {
    this.authoritiesClaimDelimiter = split;
  }
}
