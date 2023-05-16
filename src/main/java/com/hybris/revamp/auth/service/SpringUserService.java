package com.hybris.revamp.auth.service;

import com.hybris.revamp.auth.infra.SpringUser;
import com.hybris.revamp.auth.model.AppUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


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
			AppUser appUser  = appUserService.getUserByEmail(username);
//			return new SpringUser(appUser.getEmailAddress(), appUser.getPassword(), Collections.emptyList());
			return new SpringUser(appUser);
		} catch (AuthenticationException e) {
			throw new UsernameNotFoundException("Username is wrong.");
		}
	}
}
