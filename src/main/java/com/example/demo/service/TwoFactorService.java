package com.example.demo.service;


import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.util.Utils;
import org.springframework.stereotype.Service;
import dev.samstevens.totp.time.TimeProvider;

@Service
public class TwoFactorService {

    private final TimeProvider timeProvider = new SystemTimeProvider();
    private final CodeGenerator codeGenerator = new DefaultCodeGenerator(HashingAlgorithm.SHA1,6);


    //generate a random TOTP secret (Base64)
    public String generateSecret(){
        return new DefaultSecretGenerator().generate();
    }

    //generate data in Base64 QR Code format
    public String generateQrCodeDataUrl(String secret, String email){
        QrData data = new QrData.Builder()
                .label(email)
                .issuer("Digital Library")
                .secret(secret)
                .algorithm(HashingAlgorithm.SHA1)
                .digits(6)
                .period(30)
                .build();

        QrGenerator generator = new ZxingPngQrGenerator();
        byte[] imageData = new byte[0];
        try {
            imageData = generator.generate(data);
        } catch (Exception ex) {
            throw new RuntimeException("Error while generating 2FA QR Code", ex);
        }
        return Utils.getDataUriForImage(imageData, generator.getImageMimeType());
    }

    //Validates whether the provided code matches the TOTP secret within the current time window.
    public boolean verifyCode(String secret, String code){
        if(secret == null || code ==null || code.trim().length() != 6){
            return false;
        }

        long currentBucket = Math.floorDiv(timeProvider.getTime(),30L);
        try{
            for (int i = -1; i <= 1; i++){
                String validCode = codeGenerator.generate(secret, currentBucket + i);
                if (validCode.equals(code.trim())){
                    return true;
                }
            }
        } catch (Exception ex) {
            return false;
        }
        return false;
    }


}
