package com.example.demo.repository;

import com.example.demo.model.Favorite;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface FavoriteRepository extends JpaRepository<Favorite, UUID> {
}
