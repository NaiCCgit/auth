package com.hybris.revamp.auth.service;

import com.hybris.revamp.auth.infra.SpringUser;
import com.hybris.revamp.auth.model.AppUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;


@Service
public class SpringUserService implements UserDetailsService
{

	@Autowired
	private AppUserService appUserService;

	/**
	 * Sign in時會呼叫
	 */
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
	{
		try {
			AppUser user  = appUserService.getUserByEmail(username);
			return new User(user.getEmailAddress(), user.getPassword(), Collections.emptyList());
//			return new SpringUser(appUser);
		} catch (AuthenticationException e) {
			throw new UsernameNotFoundException("Username is wrong.");
		}
	}
}
