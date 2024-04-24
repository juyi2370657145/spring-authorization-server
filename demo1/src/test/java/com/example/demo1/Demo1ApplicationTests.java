package com.example.demo1;

import java.util.ArrayList;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootTest
class Demo1ApplicationTests {

  @Autowired
  PasswordEncoder passwordEncoder;

  @Test
  void contextLoads() {
    ArrayList<String> strings = new ArrayList<>();
    for (int i = 0; i < 10; i++) {
      strings.add(i + "");
    }

    Set<String> collect = strings.stream().map(String::strip).collect(Collectors.toSet());
    System.out.println(collect);
  }

  @Test
  void test1() {
    System.out.println(passwordEncoder.encode("123456"));
  }

}
