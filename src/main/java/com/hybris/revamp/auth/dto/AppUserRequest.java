package com.hybris.revamp.auth.dto;


import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

import javax.validation.constraints.NotBlank;


@Data
public class AppUserRequest {
	@Schema(description = "The email address of user.", example = "vincent@gmail.com")
	@NotBlank
	private String emailAddress;

	@Schema(description = "The password of user.", example = "123456", minLength = 6)
	@NotBlank
	private String password;

	@Schema(description = "The full name of user.", example = "Vincent Zheng")
	@NotBlank
	private String name;

//	@Schema(description = "The authority of user.", required = true)
//	@NotEmpty
//	private List<UserAuthority> authorities;

}
