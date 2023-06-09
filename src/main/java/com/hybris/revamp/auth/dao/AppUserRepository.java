package com.hybris.revamp.auth.dao;

import com.hybris.revamp.auth.model.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;


@Repository
public interface AppUserRepository extends JpaRepository<AppUser, Long>
{
	Optional<AppUser> findByEmailAddress(String email);
}
