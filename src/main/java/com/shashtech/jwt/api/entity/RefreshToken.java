package com.shashtech.jwt.api.entity;

import java.time.Instant;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity(name="TBL_REFRESH_TOKEN")
public class RefreshToken {

	@Id
	@GeneratedValue(strategy=GenerationType.AUTO)
	private Integer id;
	
	private String refreshToken;
	
	private Instant expiryDate;
	
	@OneToOne
	@JoinColumn(name="user_id")
	private User user;
}
