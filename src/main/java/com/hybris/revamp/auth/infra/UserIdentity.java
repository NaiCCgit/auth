package com.hybris.revamp.auth.infra;

import com.hybris.revamp.auth.model.AppUser;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;


/**
 * 用以取得requester的資料，透過先前token存入的SecurityContext
 * 任何service autowired此class進去就能get requester相關資料
 */
@Component
@Slf4j
@Data
public class UserIdentity
{

	private final SpringUser EMPTY_USER = new SpringUser(new AppUser());

	private SpringUser getSpringUser() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		Object principal = authentication.getPrincipal();
		log.info("UserIdentity principal:{}", principal);
		return principal.equals("anonymousUser")
				? EMPTY_USER
				: (SpringUser) principal;
	}

	public boolean isAnonymous() {
		return EMPTY_USER.equals(getSpringUser());
	}

	public String getId() {
		return getSpringUser().getId();
	}

	public String getName() {
		return getSpringUser().getName();
	}

	public String getEmail() {
		return getSpringUser().getUsername();
	}

}
