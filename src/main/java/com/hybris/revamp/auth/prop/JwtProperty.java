package com.hybris.revamp.auth.prop;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.stereotype.Component;


@Data
@AllArgsConstructor
@NoArgsConstructor
@Component
@ConfigurationProperties(prefix = "auth.jwt")
public class JwtProperty
{
	private int ttl;
	private String issuer;
	private String key;

	@NestedConfigurationProperty
	RsaProperty rsa = new RsaProperty();

	@Data
	public class RsaProperty {
		private String publicKey;
		private String privateKey;
	}
}
