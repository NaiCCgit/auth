package com.hybris.revamp.auth.controller;

import com.hybris.revamp.auth.dto.AppUserResponse;
import com.hybris.revamp.auth.dto.AuthRequest;
import com.hybris.revamp.auth.infra.JWTService;
import com.hybris.revamp.auth.dto.AppUserRequest;
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


@Tag(name = "解析憑證", description = "",
		externalDocs = @ExternalDocumentation(description = "Hybris revamp", url = "https://app.diagrams.net/#G1oL91FbzYXNhptlFWGzT0BO9VUcOjFabI#%7B%22pageId%22%3A%22kAxL3TWApweyhOxt9li8%22%7D"))
@AllArgsConstructor
@Slf4j
@RestController
public class TokenControlller {

	private final JWTService jwtService;

	private final AppUserService service;

	@RequestMapping("/")
	public String home() {
		return "Welcome Home!";
	}


	@PostMapping("/exchange")
//	public ResponseEntity<ResponseRequest<T>> exchangeToken() {
	public void exchangeToken() {

//		TransDeliveryPlanning newTransDeliveryPlanning = transDeliveryPlanningService.save(request);
//
//		ResponseRequest<TransDeliveryPlanning> response = new ResponseRequest<TransDeliveryPlanning>();
//
//		if (newTransDeliveryPlanning != null) {
//			response.setMessage(PESAN_SIMPAN_BERHASIL);
//			response.setData(newTransDeliveryPlanning);
//		} else {
//			response.setMessage(PESAN_SIMPAN_GAGAL);
//		}

//		return ResponseEntity.ok(response);
	}

	/**
	 * 從request取得帳密產生JWT
	 */
	@Operation(summary = "Generate token")
	@PostMapping("/auth/generate-token")
	public ResponseEntity<Map<String, String>> generateToken(@Valid @RequestBody AuthRequest request) {
		log.info("generateToken:{}", request);
		String token = jwtService.generateToken(request);
		Map<String, String> response = Collections.singletonMap("token", token);

		return ResponseEntity.ok(response);
	}

	@Hidden
	@Operation(summary = "Parse token")
	@PostMapping("/auth/parse-token")
	public ResponseEntity<Map<String, Object>> parseToken(@RequestBody Map<String, String> request) {
		String token = request.get("token");
		Map<String, Object> response = jwtService.parseToken(token);

		return ResponseEntity.ok(response);
	}

	@Operation(summary = "建立使用者", description = "密碼encoder為BCryptPasswordEncoder")
	@PostMapping("/auth/user")
	public ResponseEntity<AppUserResponse> createUser(@Valid @RequestBody AppUserRequest request) {
		log.info("request:{}", request);
		AppUserResponse user = service.createUser(request);

		URI location = ServletUriComponentsBuilder
				.fromCurrentRequest()
				.path("/{id}")
				.buildAndExpand(user.getId())
				.toUri();

		return ResponseEntity.created(location).body(user);
	}

	@GetMapping("/auth")
	public void publicApi() {
		log.info("publicApi");

	}

	@PostMapping("/controlled")
	public void accessControlled() {
		log.info("accessControlled");
	}

}
