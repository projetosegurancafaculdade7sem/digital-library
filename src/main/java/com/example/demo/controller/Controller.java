package com.example.demo.controller;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController("/home")
public class Controller {


    @GetMapping("/getUsers")
    public String getUsers() {
        return "Hello World!";
    }
}
