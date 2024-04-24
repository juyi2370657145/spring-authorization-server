package com.example.demo1.controller;

import java.security.Principal;
import java.util.Collections;
import java.util.Map;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * 测试接口
 *
 * @author vains
 */
@RestController
public class TestController {

  @GetMapping("/test01")
  @PreAuthorize("hasAuthority('message.read')")
  public String test01() {
    return "test01";
  }

  @GetMapping("/app")
  @PreAuthorize("hasAuthority('app')")
  public String app() {
    return "app";
  }

  @ResponseBody
  @GetMapping("/user")
  public Map<String,Object> user(Principal principal) {
    if (!(principal instanceof JwtAuthenticationToken token)) {
      return Collections.emptyMap();
    }
    return token.getToken().getClaims();
  }

}
