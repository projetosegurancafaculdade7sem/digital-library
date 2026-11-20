package com.example.demo.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
public class MailService {

    private static final Logger log = LoggerFactory.getLogger(MailService.class);

    private final JavaMailSender mailSender;
    private final String fromAddress;
    private final String resetBaseUrl;

    public MailService(JavaMailSender mailSender,
                       @Value("${mail.from:}") String fromAddress,
                       @Value("${mail.reset.base-url:}") String resetBaseUrl) {
        this.mailSender = mailSender;
        this.fromAddress = fromAddress;
        this.resetBaseUrl = resetBaseUrl;
    }

    /**
     * Envio assíncrono: a resposta de /forgot-password leva o mesmo tempo para e-mails
     * existentes e inexistentes (anti-enumeração) e uma falha de SMTP não vira erro 500.
     */
    @Async
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

        try {
            mailSender.send(message);
        } catch (MailException ex) {
            // Sem o destinatário nem o token no log (dados pessoais / segredo).
            log.error("Falha ao enviar e-mail de recuperação de senha: {}", ex.getClass().getSimpleName());
        }
    }
}
