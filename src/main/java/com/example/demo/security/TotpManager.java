package com.example.demo.security;


import org.springframework.stereotype.Component;
import org.jboss.aerogear.security.otp.Totp;
import org.jboss.aerogear.security.otp.api.Base32;


@Component
public class TotpManager {

    //generate a random secret for the user
    public String generateSecretKey(){
        return Base32.random();
    }

    public boolean verifyCode(String secret, String code){
        if (secret == null || code == null || code.trim().isEmpty()){
            return false;
        }
        Totp totp = new Totp(secret);
        try {
            return totp.verify(code.trim());
        } catch (NumberFormatException e){
            return false;
        }


    }
    public String getQrCodeUrl(String email, String secret, String appName){
        return String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s", appName, email, secret, appName);
    }
}
