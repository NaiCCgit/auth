package com.hybris.revamp.auth.infra;

import com.hybris.revamp.auth.dto.AuthRequest;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Calendar;
import java.util.Map;
import java.util.stream.Collectors;


@Service
public class JWTService {

	@Autowired
	private AuthenticationManager authenticationManager;

	private final String KEY = "ShoalterHktvMallHybrisKey";

	/**
	 * 產生期限2分鐘的 JWT
	 *
	 * @param request
	 * @return
	 */
	public String generateToken(AuthRequest request) {
		Authentication authentication = new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword());
		// authenticationManager有多種驗證方法，param會是一個Authentication介面
		// 如果要以帳密驗證，那就使用介面下的UsernamePasswordAuthenticationToken實做
		authentication = authenticationManager.authenticate(authentication);
		UserDetails userDetails = (UserDetails) authentication.getPrincipal();

		Calendar calendar = Calendar.getInstance();
		calendar.add(Calendar.MINUTE, 2);

		// Claims物件用來放payload
		Claims claims = Jwts.claims();
		claims.put("username", userDetails.getUsername());
		claims.setExpiration(calendar.getTime());
		claims.setIssuer("Shoalter-BE-II");

		// 產生密鑰: 提供一個字串,轉成 byte[]作為參數
		Key secretKey = Keys.hmacShaKeyFor(KEY.getBytes());

		// header以內建，只需提供payload & 以密鑰簽名
		return Jwts.builder()
				.setClaims(claims)
				.signWith(secretKey)
				.compact();
	}

	/**
	 * 驗證方式，以一樣的header+payload，搭配只有自己知道的密鑰，產生signature
	 * 如果跟原signature一樣就通過，如果是其他機構因為沒有密鑰，所以會產生不一樣的signature
	 *
	 * @param token
	 * @return
	 */
	public Map<String, Object> parseToken(String token) {
		// 先準備好密鑰
		Key secretKey = Keys.hmacShaKeyFor(KEY.getBytes());

		JwtParser parser = Jwts.parserBuilder()
				.setSigningKey(secretKey)
				.build();

		// 解析出JWS，getBody後得到Claims物件(放payload的)
		Claims claims = parser
				.parseClaimsJws(token)
				.getBody();

		return claims.entrySet().stream()
				.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
	}

}
