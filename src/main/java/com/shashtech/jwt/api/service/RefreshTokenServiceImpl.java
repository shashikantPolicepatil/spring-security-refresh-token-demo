package com.shashtech.jwt.api.service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.shashtech.jwt.api.entity.RefreshToken;
import com.shashtech.jwt.api.exception.TokenRefreshException;
import com.shashtech.jwt.api.repository.RefreshTokenRepository;
import com.shashtech.jwt.api.repository.UserRepository;

@Service
public class RefreshTokenServiceImpl {

	@Value("${shashtech.app.jwtRefreshTokenExpirationMs}")
	private Integer refreshDurationExpirationMS;
	
	@Autowired
	private RefreshTokenRepository refreshTokenRepository;
	
	@Autowired
	private UserRepository userRepository;
	
	public RefreshToken createRefreshToken(Integer userId) {
		RefreshToken refreshToken = new RefreshToken(0, UUID.randomUUID().toString(), Instant.now().plusMillis(refreshDurationExpirationMS), 
				userRepository.findById(userId).get());
		refreshToken = refreshTokenRepository.save(refreshToken);
		return refreshToken;
	}
	
	public RefreshToken verifyRefreshToken(RefreshToken token) {
		if(token.getExpiryDate().compareTo(Instant.now())<0) {
			refreshTokenRepository.delete(token);
			 throw new TokenRefreshException(token.getRefreshToken(), "Refresh token was expired. Please make a new signin request");
		}
		return token;
	}
	
	 @Transactional
	  public int deleteByUserId(Integer userId) {
	    return refreshTokenRepository.deleteByUser(userRepository.findById(userId).get());
	  }
	 
	 public Optional<RefreshToken> findTokenRefreshToken(String token) {
		  return refreshTokenRepository.findByRefreshToken(token);
		 
	 }
}
