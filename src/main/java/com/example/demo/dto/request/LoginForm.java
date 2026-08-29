package com.example.demo.dto.request;


import lombok.Data;

@Data
public class LoginForm {

    private String email;
    private String password;
    private String totpcode;

}
