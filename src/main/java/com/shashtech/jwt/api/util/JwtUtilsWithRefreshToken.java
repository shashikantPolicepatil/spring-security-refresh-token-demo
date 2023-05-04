package com.shashtech.jwt.api.util;

import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.shashtech.jwt.api.service.UserDetailsServiceImpl;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

@Component
public class JwtUtilsWithRefreshToken {

	private static final Logger logger = LoggerFactory.getLogger(JwtUtilsWithRefreshToken.class);

	  @Value("${shashtech.app.jwtSecret}")
	  private String jwtSecret;

	  @Value("${shashtech.app.jwtExpirationMS}")
	  private int jwtExpirationMs;

	  public String generateJwtToken(UserDetailsServiceImpl userPrincipal) {
	    return generateTokenFromUsername(userPrincipal.getUsername());
	  }

	public String generateTokenFromUsername(String username) {
		return Jwts.builder().setSubject(username).setIssuedAt(new Date())
		.setExpiration(new Date((new Date()).getTime()+jwtExpirationMs))
		.signWith(SignatureAlgorithm.HS512, jwtSecret).compact();
	}
	
	public String getUserNameFromToken(String token) {
		return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
	}

	public boolean validateJwtToken(String token) {
		try {
			Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
			return true;
		} catch(ExpiredJwtException | UnsupportedJwtException|
				MalformedJwtException| SignatureException| IllegalArgumentException ex) {
			logger.error("Unable to parse Jwt token: {}", ex.getMessage());
		}
		return false;
	}
	  
}
