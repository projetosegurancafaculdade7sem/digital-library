package com.example.demo.repository;

import com.example.demo.model.Favorite;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface FavoriteRepository extends JpaRepository<Favorite, UUID> {

    @Modifying
    @Query("delete from Favorite f where f.user.id = :userId")
    void deleteByUserId(@Param("userId") UUID userId);

    @Query("select f.bookId from Favorite f where f.user.id = :userId")
    List<String> findBookIdsByUserId(@Param("userId") UUID userId);
}
