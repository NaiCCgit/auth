package com.hybris.revamp.auth.controller;

import com.hybris.revamp.auth.dto.AppUserRequest;
import com.hybris.revamp.auth.dto.AppUserResponse;
import com.hybris.revamp.auth.dto.AuthRequest;
import com.hybris.revamp.auth.infra.JWTService;
import com.hybris.revamp.auth.service.AppUserService;
import io.swagger.v3.oas.annotations.ExternalDocumentation;
import io.swagger.v3.oas.annotations.Hidden;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.validation.Valid;
import java.net.URI;
import java.util.Collections;
import java.util.Map;


@Tag(name = "憑證API", description = "",
		externalDocs = @ExternalDocumentation(description = "Hybris revamp", url = "https://app.diagrams.net/#G1oL91FbzYXNhptlFWGzT0BO9VUcOjFabI#%7B%22pageId%22%3A%22kAxL3TWApweyhOxt9li8%22%7D"))
@AllArgsConstructor
@Slf4j
@RestController
public class TokenControlller {

	private final JWTService jwtService;

	private final AppUserService service;

	/**
	 * Welcome
	 */
	@RequestMapping("/")
	public String home() {
		return "Welcome Home!";
	}


	/**
	 * 建立"此系統的使用者"
	 */
	@Operation(summary = "建立使用者", description = "密碼encoder為BCryptPasswordEncoder")
	@PostMapping("/auth/user")
	public ResponseEntity<AppUserResponse> createUser(@Valid @RequestBody AppUserRequest request) {
		log.info("createUser:{}", request);
		AppUserResponse user = service.createUser(request);

		URI location = ServletUriComponentsBuilder
				.fromCurrentRequest()
				.path("/{id}")
				.buildAndExpand(user.getId())
				.toUri();

		return ResponseEntity.created(location).body(user);
	}

	/**
	 * 以此系統使用者的帳密，產生JWT回傳
	 */
	@Operation(summary = "Generate token", description = "以現存使用者的帳密拿到token")
	@PostMapping("/auth/login")
	public ResponseEntity<Map<String, String>> generateToken(@Valid @RequestBody AuthRequest request) {
		log.info("generateToken:{}", request);
		String token = jwtService.generateToken(request);
		Map<String, String> response = Collections.singletonMap("token", token);

		return ResponseEntity.ok(response);
	}

	/**
	 * 以此系統token，查出此系統的user資訊
	 */
	@Hidden
	@Operation(summary = "Parse token", description = "以request body的token，查出使用者資訊")
	@PostMapping("/auth/parse-token")
	public ResponseEntity<Map<String, Object>> parseToken(@RequestBody Map<String, String> request) {
		log.info("parseToken:{}", request);
		String token = request.get("token");
		Map<String, Object> response = jwtService.parseToken(token);

		return ResponseEntity.ok(response);
	}

	/**
	 * header帶"本系統token"
	 * request body帶occ token
	 * 以occ token資訊，透過mock管道，拿到customer info
	 * 以customer info產生要給mall系統的Jwt
	 * 以Jwt，透過mall api，拿到pk,uid
	 * 以pk,uid，產生JWT回傳
	 *
	 */
	@Operation(summary = "Exchange token", description = "以OCC token換取另一JWT回傳，其內包含mall內的PK和uid")
	@PostMapping("/occ/login/tokenExchange")
	public ResponseEntity<Map<String, String>> exchangeOccToken(@Valid @RequestBody Map<String, String> request) {
		String token = request.get("token");
		String exchangedToken = jwtService.exchangeToken(token);
		Map<String, String> response = Collections.singletonMap("token", exchangedToken);

		return ResponseEntity.ok(response);
	}

	@Operation(summary = "訪問不需憑證", description = "無需header token自由訪問")
	@GetMapping("/auth")
	public void publicApi() { log.info("publicApi"); }

	/**
	 * header帶此系統token才能訪問
	 */
	@Operation(summary = "訪問需帶憑證", description = "header需帶token才能訪問")
	@PostMapping("/controlled")
	public void accessControlled() {
		log.info("AccessControlled Pass");
	}

}
