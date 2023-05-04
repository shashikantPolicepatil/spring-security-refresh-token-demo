package com.shashtech.jwt.api.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;

import com.shashtech.jwt.api.entity.RefreshToken;
import com.shashtech.jwt.api.entity.User;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Integer> {

	Optional<RefreshToken> findByRefreshToken(String token);

	@Modifying
	int deleteByUser(User user);
}
