package com.hybris.revamp.auth.service;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.hybris.revamp.auth.exception.NotFoundException;
import com.hybris.revamp.auth.infra.UserIdentity;
import com.hybris.revamp.auth.prop.JwtProperty;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Calendar;
import java.util.Map;
import java.util.stream.Collectors;


@Slf4j
@Service
@RequiredArgsConstructor
public class TokenService {

	private final JwtProperty jwtProperty;

	/**
	 * 以raw occ token資訊，透過mock管道，拿到customer info
	 * 以customer info登入mall系統，拿到access_token
	 * 以access_token，透過mall api，拿到pk,uid
	 * 以pk,uid，產生JWT回傳
	 *
	 * @param token 為Occtoken
	 */
	@SneakyThrows
	public String exchangeToken(String token)
	{
		// fixme: this is mock
		CustomerProfileInfo cusInfo = this.getCustomerProfileInfo(token);
		String access_token = this.hktvOauthLogin(cusInfo.getCustomerName(), cusInfo.getPassword());
		// TODO: 抽象掉
		CustomerData curCustomer = this.hktvGetCurrentCustomer(access_token);
		String exchagedToken = this.generateOccToken(curCustomer, token);
		log.info("exchagedToken:{}", exchagedToken);
		return exchagedToken;
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
	static class CustomerProfileInfo
	{
		long id;
		String customerName;
		String password;
	}

	/**
	 * mock "use the token to get customer profile info"
	 */
	private CustomerProfileInfo getCustomerProfileInfo(String claims) {
		return new CustomerProfileInfo(99L, "cyliu@hktv.com.hk", "qwe123");
		//		repository.findCustomerProfileInfoById(claims.getSubject());
	}

	private String generateOccToken(CustomerData curCustomer, String rawOccToken) {

		log.info("Public Key: {}", jwtProperty.getRsa().getPublicKey());
		log.info("Private Key: {}", jwtProperty.getRsa().getPrivateKey());

		Claims claims = Jwts.claims();
		Calendar calendar = Calendar.getInstance();
		calendar.add(Calendar.MINUTE, jwtProperty.getTtl());

		claims.setIssuer(jwtProperty.getIssuer())
				.setExpiration(calendar.getTime());
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

		PKCS8EncodedKeySpec keySpec_private = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyStr.getBytes(StandardCharsets.UTF_8)));
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

	/**
	 * Overload 用local public key分析Rsa
	 */
	@SneakyThrows
	public Map<String, Object> parseRsaJwt(String jwtToParse) {
		return this.parseRsaJwt(jwtToParse, jwtProperty.getRsa().getPublicKey());
	}

	/**
	 * Overload 用param public key分析Rsa
	 */
	@SneakyThrows
	public Map<String, Object> parseRsaJwt(String jwtToParse, String pubK) {
		X509EncodedKeySpec keySpec_public = new X509EncodedKeySpec(Base64.getDecoder().decode(pubK.getBytes(StandardCharsets.UTF_8)));
		KeyFactory keyFactory_public = KeyFactory.getInstance("RSA");
		PublicKey publicKey_public = keyFactory_public.generatePublic(keySpec_public);

		Jws<Claims> jws = Jwts.parser()
				.setSigningKey(publicKey_public)
				.parseClaimsJws(jwtToParse);

		Claims parsedRsaJwtClaims = jws.getBody();

		return parsedRsaJwtClaims.entrySet().stream()
				.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
	}

}
