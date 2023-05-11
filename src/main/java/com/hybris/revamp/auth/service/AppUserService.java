package com.hybris.revamp.auth.service;

import com.hybris.revamp.auth.dao.AppUserRepository;
import com.hybris.revamp.auth.dto.AppUserRequest;
import com.hybris.revamp.auth.dto.AppUserResponse;
import com.hybris.revamp.auth.exception.NotFoundException;
import com.hybris.revamp.auth.model.AppUser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
@Service
public class AppUserService
{

	private AppUserRepository repository;

	private BCryptPasswordEncoder passwordEncoder;

	public AppUserService(AppUserRepository repository) {
		this.repository = repository;
		this.passwordEncoder = new BCryptPasswordEncoder();
	}

	public AppUser getUserResponseById(String id) {
		AppUser user = repository.findById(Long.valueOf(id))
				.orElseThrow(() -> new NotFoundException("Can't find user."));

		return user;
	}

	public AppUser getUserByEmail(String email) {
		return repository.findByEmailAddress(email)
				.orElseThrow(() -> new NotFoundException("Can't find user."));
	}

	public AppUserResponse createUser(AppUserRequest request) {
		Optional<AppUser> existingUser = repository.findByEmailAddress(request.getEmailAddress());
		if (existingUser.isPresent()) {
			throw new NotFoundException("This email address has been used.");
		}
		log.info("existingUser:{}", existingUser);

		AppUser user = new AppUser();
		user.setName(request.getName());
		user.setEmailAddress(request.getEmailAddress());
		user.setPassword(passwordEncoder.encode(request.getPassword()));
		repository.save(user);
		log.info("user:{}", user);

		AppUserResponse response = new AppUserResponse();
		response.setName(user.getName());
		response.setId(user.getId());
		response.setEmailAddress(user.getEmailAddress());
		log.info("response:{}", response);
		return response;
	}

//	public List<AppUser> getUserResponses(List<UserAuthority> authorities) {
//		if (authorities == null || authorities.isEmpty()) {
//			authorities = Arrays.stream(UserAuthority.values())
//					.collect(Collectors.toList());
//		}
//
//		List<AppUser> users = repository.findByAuthoritiesIn(authorities);
//		return AppUserConverter.toAppUserResponses(users);
//	}
}
