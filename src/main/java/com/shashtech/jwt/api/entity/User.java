
package com.shashtech.jwt.api.entity;

import java.util.HashSet;
import java.util.Set;

import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.Table;
import javax.validation.constraints.NotBlank;

import com.fasterxml.jackson.annotation.JsonIgnore;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name="TBL_USER")
public class User {

	@Id
	@GeneratedValue(strategy=GenerationType.AUTO)
	private Integer id;
	@NotBlank
	private String userName;
	@NotBlank
	@JsonIgnore
	private String password;
	@NotBlank
	private String email;
	
	@ManyToMany(fetch=FetchType.EAGER)
	@JoinTable(name="tbl_user_roles" , joinColumns = @JoinColumn(name = "user_id"),
			inverseJoinColumns = @JoinColumn(name = "role_id"))
	Set<Role> userRoles = new HashSet<>();
}
