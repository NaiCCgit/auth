package com.hybris.revamp.auth.infra;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.hybris.revamp.auth.dto.AuthRequest;
import com.hybris.revamp.auth.exception.NotFoundException;
import com.hybris.revamp.auth.prop.JwtProperty;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
@Service
public class JWTService {

	@Autowired
	private JwtProperty jwtProperty;

	@Autowired
	private AuthenticationManager authenticationManager;

	private static final String KEY = "ShoalterHktvMallHybrisTokenSecretKey";

	/**
	 * 產生期限200分鐘的 JWT
	 *
	 * @param request 使用者的帳密
	 * @return Jwt string
	 */
	@SneakyThrows
	public String generateToken(AuthRequest request) {
		Authentication authentication = new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword());
		// authenticationManager有多種驗證方法,param會是一個Authentication介面
		// 如果要以帳密驗證,那就使用介面下的UsernamePasswordAuthenticationToken實做
		authentication = authenticationManager.authenticate(authentication);
		// authenticate成功後的return依然是Authentication介面,但其內的principal會變成UserDetails
		UserDetails userDetails = (UserDetails) authentication.getPrincipal();

		// Claims物件用來放payload
		Claims claims = Jwts.claims();
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
		claims.put("username", userDetails.getUsername());
		claims.setIssuer("Shoalter-BE-II")
				.setExpiration(sdf.parse("2200-01-01"));

		// 產生密鑰: 提供一個字串,轉成 byte[]作為參數
		Key secretKey = Keys.hmacShaKeyFor(KEY.getBytes());

		// header已內建，只需提供payload & 以密鑰簽名
		return Jwts.builder()
				.setClaims(claims)
				.signWith(secretKey)
				.compact();
	}

	/**
	 * 驗證方式，以一樣的header+payload，搭配只有自己知道的密鑰，產生signature
	 * 如果跟原signature一樣就通過，如果是其他機構因為沒有密鑰，所以會產生不一樣的signature
	 *
	 * @param token RequestHeader Authorization欄位的"Bear "後的類亂碼
	 * @return 解析成功的話,回傳payload(發行者,過期日...etc)
	 */
	public Map<String, Object> parseToken(String token) {
		// 先準備好密鑰
		Key secretKey = Keys.hmacShaKeyFor(KEY.getBytes());
		// 以密鑰建立 parser
		JwtParser parser = Jwts.parserBuilder()
				.setSigningKey(secretKey)
				.build();

		// 解析出JWS，如果失敗會SignatureException,如果過期會ExpiredJwtException
		// JWS.getBody後得到Claims物件(放payload的)
		Claims claims = parser
				.parseClaimsJws(token)
				.getBody();

		return claims.entrySet().stream()
				.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
	}

}
