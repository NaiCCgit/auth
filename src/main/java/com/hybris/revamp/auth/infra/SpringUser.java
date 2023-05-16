package com.hybris.revamp.auth.infra;


import com.hybris.revamp.auth.model.AppUser;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;


public class SpringUser implements UserDetails
{
	private AppUser appUser;

	public SpringUser(AppUser appUser) {
		this.appUser = appUser;
	}

	public SpringUser(String name, String password, Collection<? extends GrantedAuthority> authorities) {
		this.appUser = appUser;
	}

	public String getId() {
		return String.valueOf(appUser.getId());
	}

	public String getName() {
		return appUser.getName();
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return Collections.emptyList();
//		return appUser.getAuthorities().stream()
//				.map(auth -> new SimpleGrantedAuthority(auth.name()))
//				.collect(Collectors.toList());
	}

	@Override
	public String getPassword() {
		return appUser.getPassword();
	}

	@Override
	public String getUsername() {
		return appUser.getEmailAddress();
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}
}

