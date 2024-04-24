package com.example.demo1resource.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 测试接口
 *
 * @author vains
 */
@RestController
public class TestController {

  @GetMapping("/test01")
  @PreAuthorize("hasAuthority('test01')")
  public String test01() {
    return "test01";
  }

  @GetMapping("/test02")
  @PreAuthorize("hasAuthority('test02')")
  public String test02() {
    return "test02";
  }

  @GetMapping("/app")
  @PreAuthorize("hasAuthority('app')")
  public String app() {
    return "app";
  }

}

