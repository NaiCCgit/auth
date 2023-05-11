package com.hybris.revamp.auth.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import java.util.Collection;
import java.util.Collections;


@NoArgsConstructor
@AllArgsConstructor
@Data
@Entity
@Table(name = "APP_USER")
public class AppUser {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "ID")
	private long id;

	@Column(name = "EMAIL_ADDRESS")
	private String emailAddress;

	@Column(name = "PASSWORD")
	private String password;

	@Column(name = "NAME")
	private String name;

	public Collection<? extends GrantedAuthority> getAuthorities()
	{
		return Collections.EMPTY_LIST;
	}
}
