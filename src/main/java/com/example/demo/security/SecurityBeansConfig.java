package com.example.demo.security;


import lombok.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class SecurityBeansConfig {


    @Value("${security.argon2.salt-length:16}")
    private int saltLength;

    @Value("${security.argon2.hash-length:32}")
    private int hashLength;

    @Value("${security.argon2.parallelism:1}")
    private int parallelism;

    @Value("${security.argon2.memory:65536}")
    private int memory;

    @Value("${security.argon2.iterations:3}")
    private int iterations;

    // req 1.1 e 1.2 hash criptográfico seguro

    //Argon2id configuration

// Argon2id Configuration (Argon2PasswordEncoder):

//saltLength (16 bytes / 128 bits): Meets RFC 9106 recommendations to mitigate rainbow table attacks.
//hashLength (32 bytes / 256 bits): Provides resistance against collision and pre-image attacks.
//parallelism (1 thread): Optimized to limit CPU usage in concurrent web environments.
//memory (65536 KB / 64 MB): High memory cost to make GPU and ASIC hardware attacks unfeasible.
//iterations (3 repetitions): Ensures a response time of < 500ms per login without compromising brute-force resistance.
    @Bean
    public PasswordEncoder passwordEncoder(){

        return new Argon2PasswordEncoder(
                saltLength,
                hashLength,
                parallelism,
                memory,
                iterations
        );
    }
}
