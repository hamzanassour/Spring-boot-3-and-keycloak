package com.leyton.salescope;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class SalescopeApplication {

    public static void main(String[] args) {
        SpringApplication.run(SalescopeApplication.class, args);
    }

    @GetMapping("/test")
    @PreAuthorize("hasRole('admin')")
    public String test(){
        return "hhhhh";
    }

}
