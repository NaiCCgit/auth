package com.hybris.revamp.auth.service;

import com.hybris.revamp.auth.dto.CipherRequest;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;


@Slf4j
@RequiredArgsConstructor
@Service
public class CipherService
{
	static String SECRETKEY  = "encryptdecrypttokensecretkey";

	@SneakyThrows
	public String parseCipherRequest(CipherRequest request){
		return this.decode(request.getToken());
	}

	@SneakyThrows
	private String decode(String cipher){
		byte[] decodedBytes = Base64.getDecoder().decode(cipher.getBytes(StandardCharsets.UTF_8));
		return new String(decodedBytes);
	}
	private String decrypt(String cipher){
		byte[] decodedKey = Base64.getDecoder().decode(SECRETKEY.getBytes(StandardCharsets.UTF_8));
		Key key = Keys.hmacShaKeyFor(decodedKey);
		return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(cipher).getBody().getSubject();
	}

	public CipherRequest encode(String raw){
		String encoded = Base64.getEncoder().encodeToString(raw.getBytes());
		return new CipherRequest(encoded);
	}

}
