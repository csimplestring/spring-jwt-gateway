package com.acm.infra.proxy;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Application {

    // JWT verification, rate limit, dynamic routing, actuator
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
