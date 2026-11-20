package com.example.demo.service;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import dev.samstevens.totp.util.Utils;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.OptionalLong;

/**
 * TOTP (RFC 6238) compatível com Microsoft Authenticator / Google Authenticator.
 * O URI otpauth é intencionalmente mínimo (secret + issuer): apps da Microsoft
 * falham ao escanear QR com parâmetros extras (algorithm/digits/period).
 */
@Service
public class TwoFactorService {

    private static final String ISSUER = "DigitalLibrary";
    private static final int PERIOD_SECONDS = 30;
    private static final int DIGITS = 6;
    private static final int QR_SIZE = 250;
    private static final int ALLOWED_DISCREPANCY = 2;

    private final TimeProvider timeProvider = new SystemTimeProvider();
    private final CodeGenerator codeGenerator = new DefaultCodeGenerator(HashingAlgorithm.SHA1, DIGITS);
    private final CodeVerifier codeVerifier;

    public TwoFactorService() {
        DefaultCodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
        verifier.setTimePeriod(PERIOD_SECONDS);
        verifier.setAllowedTimePeriodDiscrepancy(ALLOWED_DISCREPANCY);
        this.codeVerifier = verifier;
    }

    public String generateSecret() {
        return new DefaultSecretGenerator().generate();
    }

    /**
     * URI no formato aceito pelo Microsoft Authenticator:
     * otpauth://totp/Issuer:email?secret=BASE32&issuer=Issuer
     */
    public String buildOtpAuthUri(String secret, String email) {
        String normalizedSecret = normalizeSecret(secret);
        String label = urlEncode(ISSUER) + ":" + urlEncode(email);
        return "otpauth://totp/" + label
                + "?secret=" + normalizedSecret
                + "&issuer=" + urlEncode(ISSUER);
    }

    public String generateQrCodeDataUrl(String secret, String email) {
        String uri = buildOtpAuthUri(secret, email);
        try {
            BitMatrix matrix = new QRCodeWriter().encode(uri, BarcodeFormat.QR_CODE, QR_SIZE, QR_SIZE);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(matrix, "PNG", out);
            return Utils.getDataUriForImage(out.toByteArray(), "image/png");
        } catch (Exception ex) {
            throw new RuntimeException("Error while generating 2FA QR Code", ex);
        }
    }

    public boolean verifyCode(String secret, String code) {
        if (secret == null || code == null) {
            return false;
        }
        String normalizedCode = code.trim().replace(" ", "");
        if (normalizedCode.length() != DIGITS || !normalizedCode.chars().allMatch(Character::isDigit)) {
            return false;
        }
        try {
            return codeVerifier.isValidCode(normalizeSecret(secret), normalizedCode);
        } catch (Exception ex) {
            return false;
        }
    }

    /**
     * Igual a {@link #verifyCode}, mas devolve a janela de tempo (time step) do código aceito.
     * Usado no login para impedir a reutilização do mesmo código (replay).
     */
    public OptionalLong matchingTimeStep(String secret, String code) {
        if (secret == null || code == null) {
            return OptionalLong.empty();
        }
        String normalizedCode = code.trim().replace(" ", "");
        if (normalizedCode.length() != DIGITS || !normalizedCode.chars().allMatch(Character::isDigit)) {
            return OptionalLong.empty();
        }
        String normalizedSecret = normalizeSecret(secret);
        long current = Math.floorDiv(timeProvider.getTime(), PERIOD_SECONDS);
        OptionalLong match = OptionalLong.empty();
        // Percorre a janela inteira (sem parar no primeiro acerto) para manter tempo constante.
        for (long step = current - ALLOWED_DISCREPANCY; step <= current + ALLOWED_DISCREPANCY; step++) {
            try {
                String expected = codeGenerator.generate(normalizedSecret, step);
                if (MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),
                        normalizedCode.getBytes(StandardCharsets.US_ASCII)) && match.isEmpty()) {
                    match = OptionalLong.of(step);
                }
            } catch (Exception ex) {
                return OptionalLong.empty();
            }
        }
        return match;
    }

    private static String normalizeSecret(String secret) {
        return secret.trim().replace(" ", "").toUpperCase();
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
