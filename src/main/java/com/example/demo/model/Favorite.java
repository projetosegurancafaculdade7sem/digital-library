package com.example.demo.model;

import jakarta.persistence.*;
import lombok.Data;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "tb_favorites")
@Data
public class Favorite {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false)
    private String bookId; // ou o campo correspondente ao livro/item favorito

    @Column(nullable = false, updatable = false)
    private Instant createdAt = Instant.now();
}
