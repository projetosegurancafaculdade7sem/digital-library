package com.example.demo.service;


import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class BookService {


    private final AuditService auditService;

    public void logBookAccess(UUID userId, String bookIsbn, String ipAddress, String userAgent){

    }
}
