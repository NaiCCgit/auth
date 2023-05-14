package com.hybris.revamp.auth.infra;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.hybris.revamp.auth.dto.AuthRequest;
import com.hybris.revamp.auth.exception.NotFoundException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.crossstore.ChangeSetPersister;
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
import org.springframework.web.client.RestTemplate;

import java.security.Key;
import java.util.Calendar;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
@Service
public class JWTService {

	private final UserIdentity userIdentity;

	@Autowired
	private AuthenticationManager authenticationManager;

	private static final String KEY = "ShoalterHktvMallHybrisTokenSecretKey";

	// fixme: need key to decrypt Occ Token
	private static final String HKTV_KEY = "ShoalterHktvMallHybrisTokenSecretKey";

	/**
	 * 產生期限200分鐘的 JWT
	 *
	 * @param request
	 * @return
	 */
	public String generateToken(AuthRequest request) {
		Authentication authentication = new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword());
		// authenticationManager有多種驗證方法,param會是一個Authentication介面
		// 如果要以帳密驗證,那就使用介面下的UsernamePasswordAuthenticationToken實做
		authentication = authenticationManager.authenticate(authentication);
		// authenticate成功後的return依然是Authentication介面,但其內的principal會變成UserDetails
		UserDetails userDetails = (UserDetails) authentication.getPrincipal();

		Calendar calendar = Calendar.getInstance();
		calendar.add(Calendar.MINUTE, 200);

		// Claims物件用來放payload
		Claims claims = Jwts.claims();
		claims.put("username", userDetails.getUsername());
		claims.setExpiration(calendar.getTime());
		claims.setIssuer("Shoalter-BE-II");

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

	/**
	 * 進入此方法須header先帶了 in situ 的token
	 * param 為occtoken被解析出claims
	 * claims透過mock管道，拿到customer info
	 * 以customer info產生要給mall系統的Jwt(call mall 的 login api?)
	 * header帶Jwt，透過mall api，拿到pk,uid
	 * 以pk,uid建立Jwt回傳
	 *
	 * @param token 為Occtoken
	 */
	@SneakyThrows
	public String exchangeToken(String token)
	{
		Claims claims = this.parseOccToken(token);
		CustomerProfileInfo cusInfo = this.getCustomerProfileInfo(claims);
		// fixme: get HktvToken?
		String ROLE_CUSTOMERGROUP_TOKEN = this.hktvCustomerLogin(cusInfo.getCustomerName(), cusInfo.getPassword());
		// fixme: call Api with header token
		CustomerData curCustomer = hktvGetCurrentCustomer(ROLE_CUSTOMERGROUP_TOKEN);
		String exchagedToken = this.generateOccToken(curCustomer);
		log.info("exchagedToken{}", exchagedToken);
		return exchagedToken;
	}

	/**
	 * 進入此方法須header先帶了 in situ 的token
	 * 方法參數為Occtoken
	 */
	public Claims parseOccToken(String token) {
		// HKTV密鑰
		Key secretKey = Keys.hmacShaKeyFor(HKTV_KEY.getBytes());
		JwtParser parser = Jwts.parserBuilder()
				.setSigningKey(secretKey)
				.build();

		// 解析出JWS，如果失敗會SignatureException,如果過期會ExpiredJwtException
		JwsHeader header = parser.parseClaimsJws(token).getHeader();
		Claims claims = parser.parseClaimsJws(token).getBody();
		log.info("OCC token header:{}", header);
		log.info("OCC token payload:{}", claims);

		return claims;
	}

	/**
	 * mock 到hktv拿到代表customer的token
	 */
	static String hktvCustomerLogin(String n, String p){ return "12345798"; }
	/**
	 * header帶token，到hktv拿到CustomerData
	 */
	@SneakyThrows
	static CustomerData hktvGetCurrentCustomer(String mallToken)
	{
		String url = "http://localhost:9112/hktvwebservices/v1/hktv/customers/current";
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_JSON);
		headers.set("Authorization", "Bearer " + mallToken);
		HttpEntity<String> entity = new HttpEntity<>("parameters", headers);

		RestTemplate restTemplate = new RestTemplate();
		ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);
		if(response.getStatusCode().is2xxSuccessful() && response.hasBody()){
			return new ObjectMapper().readValue(response.getBody(), CustomerData.class);
		}
		throw new NotFoundException("fail to get CurrentCustomer from HKTV");
	}

	/**
	 * mock "use the token to get customer profile info"
	 */
	@Data
	static class CustomerData{
		String customerId;
		String uid;
	}

	/**
	 * mock "use the token to get customer profile info"
	 */
	@Data
	@AllArgsConstructor
	class CustomerProfileInfo
	{
		long id;
		String customerName;
		String password;
	}

	/**
	 * mock "use the token to get customer profile info"
	 */
	private CustomerProfileInfo getCustomerProfileInfo(Claims claims) {
		return new CustomerProfileInfo(99l, "default", "default");
//		repository.findCustomerProfileInfoById(claims.getSubject());
	}

	private String generateOccToken(CustomerData curCustomer) {

		Calendar calendar = Calendar.getInstance();
		calendar.add(Calendar.MINUTE, 200);

		// Claims物件用來放payload
		Claims claims = Jwts.claims();
		claims.put("username", userIdentity.getName());
		claims.put("PK", curCustomer.getCustomerId());
		claims.put("uid", curCustomer.getUid());
		claims.setExpiration(calendar.getTime());
		claims.setIssuer("Shoalter-BE-II");

		// 產生密鑰: 提供一個字串,轉成 byte[]作為參數
		Key secretKey = Keys.hmacShaKeyFor(HKTV_KEY.getBytes());

		// header已內建，只需提供payload & 以密鑰簽名
		return Jwts.builder()
				.setClaims(claims)
				.signWith(secretKey)
				.compact();
	}

}
