package com.hybris.revamp.auth.controller;

import com.hybris.revamp.auth.dto.CipherRequest;
import com.hybris.revamp.auth.service.CipherService;
import com.hybris.revamp.auth.prop.JwtProperty;
import com.hybris.revamp.auth.service.TokenService;
import io.swagger.v3.oas.annotations.ExternalDocumentation;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;
import java.util.Collections;
import java.util.Map;


@Tag(name = "憑證API", description = "與mall系統串接", externalDocs = @ExternalDocumentation(description = "Hybris revamp", url = "https://app.diagrams.net/#G1oL91FbzYXNhptlFWGzT0BO9VUcOjFabI#%7B%22pageId%22%3A%22kAxL3TWApweyhOxt9li8%22%7D"))
@AllArgsConstructor
@Slf4j
@RestController
public class TokenController
{

	private final CipherService cipherService;

	private final JwtProperty jwtProperty;

	private final TokenService tokenService;


	/**
	 * request body帶encoded occ token
	 * decode後
	 * 以occ token資訊，透過mock管道，拿到customer info
	 * 以customer info登入mall系統，拿到access_token
	 * 以access_token，透過mall api，拿到pk,uid
	 * 以pk,uid，產生JWT回傳
	 */
	@Operation(summary = "Exchange token", description = "以OCC token換取另一JWT回傳，其內包含mall內的PK和uid")
	@PostMapping("/occ/login/tokenExchange")
	public ResponseEntity<Map<String, String>> exchangeOccToken(@Valid @RequestBody CipherRequest request) {
		// 測試時通過  9112/hktvwebservices/oauth/token 拿到 QCM
		String token = cipherService.parseCipherRequest(request);
		log.info("Request Transfer to SimpleText:{}", token);
		String exchangedToken = tokenService.exchangeToken(token);
		Map<String, String> response = Collections.singletonMap("token", exchangedToken);

		return ResponseEntity.ok(response);
	}

	@Operation(summary = "Parse RS256 token", description = "local測試用 解析tokenExchange的response，確認是否有uid, pk, raw-occ-token")
	@PostMapping("/occ/parse-rsa")
	public ResponseEntity<Map<String, Object>> parseOccToken(@RequestBody Map<String, String> request) {
		String rsaJwt = request.get("rsaJwt");
		String pubK = request.get("pubK");
		var claimResult = tokenService.parseRsaJwt(rsaJwt, pubK);
		log.info("claimResult:{}", claimResult);
		return ResponseEntity.ok(claimResult);
	}

	@Operation(summary = "BEFORE exchange token", description = "local測試用 把raw access-token轉成encode後提供給exchangeOccToken測試")
	@GetMapping ("/occ/before-tokenExchange")
	public ResponseEntity<CipherRequest> encode(@RequestParam("raw") String raw) {
		CipherRequest cipher = cipherService.encode(raw);
		log.info("cipher:{}", cipher);
		return ResponseEntity.ok(cipher);
	}

	/**
	 * 測試用，確認設定屬性
	 */

	@Operation(summary = "getkey")
	@GetMapping ("/occ/getkey")
	public void encode() {
		log.info("jwtProperty:{}", jwtProperty);
		log.info("rsaProperty:{}", jwtProperty.getRsa());
		log.info("publicKey:{}", jwtProperty.getRsa().getPublicKey());
	}

}
