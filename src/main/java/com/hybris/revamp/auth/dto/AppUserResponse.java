package com.hybris.revamp.auth.dto;

import lombok.Data;

import java.util.List;

@Data
public class AppUserResponse
{

	private Long id;
	private String emailAddress;
	private String name;
//	private List<UserAuthority> authorities;
}
