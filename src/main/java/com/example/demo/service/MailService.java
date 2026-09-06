package com.example.demo.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class MailService {

    private final JavaMailSender mailSender;
    private final String fromAddress;
    private final String resetBaseUrl;

    public MailService(JavaMailSender mailSender,
                       @Value("${mail.from}") String fromAddress,
                       @Value("${mail.reset.base-url:http://localhost:8080/reset-password?token=}") String resetBaseUrl) {
        this.mailSender = mailSender;
        this.fromAddress = fromAddress;
        this.resetBaseUrl = resetBaseUrl;
    }

    public void sendPasswordResetEmail(String to, String token) {
        String resetLink = resetBaseUrl + token;

        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromAddress);
        message.setTo(to);
        message.setSubject("Recuperação de senha - Digital Library");
        message.setText(
                "Olá,\n\n" +
                        "Para redefinir sua senha, clique no link abaixo (válido por 15 minutos):\n" +
                        resetLink + "\n\n" +
                        "Se você não solicitou a mudança, ignore este e‑mail.\n\n" +
                        "Atenciosamente,\n" +
                        "Equipe Digital Library"
        );

        mailSender.send(message);
    }
}
