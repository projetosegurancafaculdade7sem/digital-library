package com.example.demo.dto.request;


import lombok.Data;

@Data
public class ResetPasswordForm {

    private String token;
    private String newPassword;
    private String confirmPassword;
}
