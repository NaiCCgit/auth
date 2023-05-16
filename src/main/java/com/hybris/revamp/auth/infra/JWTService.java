package com.hybris.revamp.auth.infra;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.hybris.revamp.auth.dto.AuthRequest;
import com.hybris.revamp.auth.exception.NotFoundException;
import com.hybris.revamp.auth.prop.JwtProperty;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
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

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Calendar;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
@Service
public class JWTService {

	private final JwtProperty jwtProperty;
	private final UserIdentity userIdentity;
	private final AuthenticationManager authenticationManager;
//	@Autowired
//	private UserIdentity userIdentity;
//
//	@Autowired
//	private AuthenticationManager authenticationManager;

	private static final String KEY = "ShoalterHktvMallHybrisTokenSecretKey";

	// fixme: need key to decrypt Occ Token
	// TODO: RSA256
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
		log.info("userIdentity:{}", userIdentity);
//		Claims claims = this.parseOccToken(token);
		// fixme: this is mock
		CustomerProfileInfo cusInfo = this.getCustomerProfileInfo(token);
		String access_token = this.hktvOauthLogin(cusInfo.getCustomerName(), cusInfo.getPassword());
		CustomerData curCustomer = this.hktvGetCurrentCustomer(access_token);
		String exchagedToken = this.generateOccToken(curCustomer, token);
		log.info("exchagedToken:{}", exchagedToken);
		return exchagedToken;
	}

	// TODO: occ不是Jwt，隨便加密隨便解密，raw大致長像 0008c8d8-e0c7-48a1-a62b-516a69a6b87a
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
	 * 到hktv拿到代表customer的token
	 */
	@SneakyThrows
	String hktvOauthLogin(String username, String password) {
		String url = "https://localhost:9112/hktvwebservices/oauth/token";
		HktvTokenRequest reqParam = new HktvTokenRequest("password", username, password);
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		this.addBasicAuth(username, password, headers);
		log.info("headers{}", headers);
		// application/x-www-form-urlencoded格式的requestBody
		MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
		map.add("grant_type","password");
		map.add("username",username);
		map.add("password",password);
		HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);
		log.info("request{}", request);

		RestTemplate restTemplate = new RestTemplate();
		log.info("Hktv Token RequestParam:{}", reqParam);
		ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.POST, request, String.class);
		if(response.getStatusCode().is2xxSuccessful() && response.hasBody()){
			HktvTokenResponse responseObj = new ObjectMapper().readValue(response.getBody(), HktvTokenResponse.class);
			log.info("Hktv Token ResponseObj:{}", responseObj);
			return responseObj.getAccess_token();
		}
		throw new NotFoundException("Fail to get Oauth token from HKTV");
	}

	/**
	 * HTTP Basic Authentication
	 */
	private HttpHeaders addBasicAuth(String username, String password, HttpHeaders headers) {
		String auth = username + ":" + password;
		var encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());
		String authHeader = "Basic " + encodedAuth;
//		headers.set( "Authorization", authHeader );
		// fixme: Figure out Basic Auth logic?
		headers.set( "Authorization", "Basic aGt0dl9pb3M6SCphSyMpSE0yNDg=");
		return headers;
	}

	@Data
	@AllArgsConstructor
	static class HktvTokenRequest
	{
		String grant_type;
		String username;
		String password;
	}
	@Data
	@NoArgsConstructor
	@AllArgsConstructor
	static class HktvTokenResponse
	{
		String access_token;
		String token_type;
		String refresh_token;
		Long expires_in;
	}


	/**
	 * header帶token，到hktv拿到CustomerData
	 */
	@SneakyThrows
	static CustomerData hktvGetCurrentCustomer(String access_token)
	{
		String url = "https://localhost:9112/hktvwebservices/v1/hktv/customers/current";
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_JSON);
		headers.set("Authorization", "Bearer " + access_token);
		HttpEntity<String> entity = new HttpEntity<>("parameters", headers);

		RestTemplate restTemplate = new RestTemplate();
		log.info("Hktv CurrentCustomer Request headers:{}", headers);
		ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);
		if(response.getStatusCode().is2xxSuccessful() && response.hasBody()){
			CustomerData customerData = new ObjectMapper().readValue(response.getBody(), CustomerData.class);
			log.info("Hktv CurrentCustomer Response:{}", customerData);
			return customerData;
		}
		throw new NotFoundException("Fail to get CurrentCustomer from HKTV");
	}

	/**
	 * Hktv CurrentCustomer Response Body
	 */
	@Data
	@AllArgsConstructor
	@NoArgsConstructor
	@JsonIgnoreProperties(ignoreUnknown = true)
	static class CustomerData{
		String customerId;
		String uid;
		String muid;
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
	private CustomerProfileInfo getCustomerProfileInfo(String claims) {
		return new CustomerProfileInfo(99l, "cyliu@hktv.com.hk", "qwe123");
//		repository.findCustomerProfileInfoById(claims.getSubject());
	}

	@SneakyThrows
	private String generateOccToken(CustomerData curCustomer, String rawOccToken) {

		log.info("Public Key: {}", jwtProperty.getRsa().getPublicKey());
		log.info("Private Key: {}", jwtProperty.getRsa().getPrivateKey());

		String someProperyValue = "someName";
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
		Claims claims = Jwts.claims();
		claims.setIssuer("Shoalter-BE-II")
				.setExpiration(sdf.parse("2200-01-01"));
		// TODO: 不確定CustomerId, Muid哪個是PK
		claims.put("PK", curCustomer.getCustomerId());
		claims.put("muid", curCustomer.getMuid());
		claims.put("uid", curCustomer.getUid());
		claims.put("raw-occ-token", rawOccToken);

		String generatedRsaJwt = generateRsaJwt(claims, jwtProperty.getRsa().getPrivateKey());
		log.info("generatedRsaJwt: {}", generatedRsaJwt);
		return generatedRsaJwt;

	}

	/**
	 * 以private key建立RSA Jwt
	 */
	@SneakyThrows
	private String generateRsaJwt(Claims claims, String privateKeyStr) {

		PKCS8EncodedKeySpec keySpec_private = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyStr.getBytes("UTF-8")));
		KeyFactory keyFactory_private = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = keyFactory_private.generatePrivate(keySpec_private);

		String generatedRsaJwt = Jwts.builder()
				.setHeaderParam("typ", "JWT")
				.setClaims(claims)
				.signWith(SignatureAlgorithm.RS256, privateKey)
				.compact();
		log.info("generatedRsaJwt:{}", generatedRsaJwt);
		return generatedRsaJwt;
	}

	@SneakyThrows
	public Map<String, Object> parseRsaJwt(String jwtToParse) {
		Claims parsedRsaJwtClaims = null;

		X509EncodedKeySpec keySpec_public = new X509EncodedKeySpec(Base64.getDecoder().decode(jwtProperty.getRsa().getPublicKey().getBytes("UTF-8")));
		KeyFactory keyFactory_public = KeyFactory.getInstance("RSA");
		PublicKey publicKey_public = keyFactory_public.generatePublic(keySpec_public);

		Jws<Claims> jws = Jwts.parser()
				.setSigningKey(publicKey_public)
				.parseClaimsJws(jwtToParse);

		parsedRsaJwtClaims = jws.getBody();

		return parsedRsaJwtClaims.entrySet().stream()
				.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
	}

	@SneakyThrows
	public Map<String, Object> parseRsaJwt(String jwtToParse, String pubK) {
		Claims parsedRsaJwtClaims = null;

		X509EncodedKeySpec keySpec_public = new X509EncodedKeySpec(Base64.getDecoder().decode(pubK.getBytes("UTF-8")));
		KeyFactory keyFactory_public = KeyFactory.getInstance("RSA");
		PublicKey publicKey_public = keyFactory_public.generatePublic(keySpec_public);

		Jws<Claims> jws = Jwts.parser()
				.setSigningKey(publicKey_public)
				.parseClaimsJws(jwtToParse);

		parsedRsaJwtClaims = jws.getBody();

		return parsedRsaJwtClaims.entrySet().stream()
				.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
	}

}
