/*
 * Copyright 2004-present the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.client.registration;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import net.minidev.json.JSONObject;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.RequestEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.util.Assert;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Allows creating a {@link ClientRegistration.Builder} from an <a href=
 * "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig">OpenID
 * Provider Configuration</a> or
 * <a href="https://tools.ietf.org/html/rfc8414#section-3">Authorization Server
 * Metadata</a> based on provided issuer.
 *
 * @author Rob Winch
 * @author Josh Cummings
 * @author Rafiullah Hamedy
 * @author Evgeniy Cheban
 * @since 5.1
 */
public final class ClientRegistrations {

	private static final String OIDC_METADATA_PATH = "/.well-known/openid-configuration";

	private static final String OAUTH_METADATA_PATH = "/.well-known/oauth-authorization-server";

	private static final RestTemplate rest = new RestTemplate();

	static {
		SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
		requestFactory.setConnectTimeout(30_000);
		requestFactory.setReadTimeout(30_000);
		rest.setRequestFactory(requestFactory);
	}

	private static final ParameterizedTypeReference<Map<String, Object>> typeReference = new ParameterizedTypeReference<>() {
	};

	private ClientRegistrations() {
	}

	/**
	 * Creates a {@link ClientRegistration.Builder} using the provided map representation
	 * of an <a href=
	 * "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse">OpenID
	 * Provider Configuration Response</a> to initialize the
	 * {@link ClientRegistration.Builder}.
	 *
	 * <p>
	 * This is useful when the OpenID Provider Configuration is not available at a
	 * well-known location, or if custom validation is needed for the issuer location
	 * (e.g. if the issuer is only accessible from a back-channel URI that is different
	 * from the issuer value in the configuration).
	 * </p>
	 *
	 * <p>
	 * Example usage:
	 * </p>
	 * <pre>
	 * RequestEntity&lt;Void&gt; request = RequestEntity.get(metadataEndpoint).build();
	 * ParameterizedTypeReference&lt;Map&lt;String, Object&gt;&gt; typeReference = new ParameterizedTypeReference&lt;&gt;() {};
	 * Map&lt;String, Object&gt; configuration = rest.exchange(request, typeReference).getBody();
	 * // Validate configuration.get("issuer") as per in the OIDC specification
	 * ClientRegistration registration = ClientRegistrations.fromOidcConfiguration(configuration)
	 *     .clientId("client-id")
	 *     .clientSecret("client-secret")
	 *     .build();
	 * </pre>
	 * @param the OpenID Provider configuration map
	 * @return the {@link ClientRegistration} built from the configuration
	 */
	public static ClientRegistration.Builder fromOidcConfiguration(Map<String, Object> configuration) {
		OIDCProviderMetadata metadata = parse(configuration, OIDCProviderMetadata::parse);
		ClientRegistration.Builder builder = withProviderConfiguration(metadata, metadata.getIssuer().getValue());
		builder.jwkSetUri(metadata.getJWKSetURI().toASCIIString());
		if (metadata.getUserInfoEndpointURI() != null) {
			builder.userInfoUri(metadata.getUserInfoEndpointURI().toASCIIString());
		}
		return builder;
	}

	/**
	 * Creates a {@link ClientRegistration.Builder} using the provided <a href=
	 * "https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a>
	 * by making an <a href=
	 * "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest">OpenID
	 * Provider Configuration Request</a> and using the values in the <a href=
	 * "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse">OpenID
	 * Provider Configuration Response</a> to initialize the
	 * {@link ClientRegistration.Builder}.
	 *
	 * <p>
	 * For example, if the issuer provided is "https://example.com", then an "OpenID
	 * Provider Configuration Request" will be made to
	 * "https://example.com/.well-known/openid-configuration". The result is expected to
	 * be an "OpenID Provider Configuration Response".
	 * </p>
	 *
	 * <p>
	 * Example usage:
	 * </p>
	 * <pre>
	 * ClientRegistration registration = ClientRegistrations.fromOidcIssuerLocation("https://example.com")
	 *     .clientId("client-id")
	 *     .clientSecret("client-secret")
	 *     .build();
	 * </pre>
	 * @param issuer the <a href=
	 * "https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a>
	 * @return a {@link ClientRegistration.Builder} that was initialized by the OpenID
	 * Provider Configuration.
	 */
	public static ClientRegistration.Builder fromOidcIssuerLocation(String issuer) {
		Assert.hasText(issuer, "issuer cannot be empty");
		return getBuilder(issuer, oidc(issuer));
	}

	/**
	 * Creates a {@link ClientRegistration.Builder} using the provided <a href=
	 * "https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a>
	 * by querying three different discovery endpoints serially, using the values in the
	 * first successful response to initialize. If an endpoint returns anything other than
	 * a 200 or a 4xx, the method will exit without attempting subsequent endpoints.
	 *
	 * The three endpoints are computed as follows, given that the {@code issuer} is
	 * composed of a {@code host} and a {@code path}:
	 *
	 * <ol>
	 * <li>{@code host/.well-known/openid-configuration/path}, as defined in
	 * <a href="https://tools.ietf.org/html/rfc8414#section-5">RFC 8414's Compatibility
	 * Notes</a>.</li>
	 * <li>{@code issuer/.well-known/openid-configuration}, as defined in <a href=
	 * "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest">
	 * OpenID Provider Configuration</a>.</li>
	 * <li>{@code host/.well-known/oauth-authorization-server/path}, as defined in
	 * <a href="https://tools.ietf.org/html/rfc8414#section-3.1">Authorization Server
	 * Metadata Request</a>.</li>
	 * </ol>
	 *
	 * Note that the second endpoint is the equivalent of calling
	 * {@link ClientRegistrations#fromOidcIssuerLocation(String)}.
	 *
	 * <p>
	 * Example usage:
	 * </p>
	 * <pre>
	 * ClientRegistration registration = ClientRegistrations.fromIssuerLocation("https://example.com")
	 *     .clientId("client-id")
	 *     .clientSecret("client-secret")
	 *     .build();
	 * </pre>
	 * @param issuer
	 * @return a {@link ClientRegistration.Builder} that was initialized by one of the
	 * described endpoints
	 */
	// 다음 3가지 엔드포인트를 순차적으로 수행 - ProviderMetadata 를 구하기 위함.
	// 1. oidc(): 표준 OIDC 엔드포인트 (/.well-known/openid-configuration)
	// 2. oidcRfc8414(): RFC 8414 호환 OIDC 엔드포인트 - 이건 문서에서 MAY 라서 지원 해도 그만 안해도 그만임. RFC 8414는 OAuth 2.0 관련임. OCID랑은 무관함.
	// 3. oauth(): OAuth2 엔드포인트 (/.well-known/oauth-authorization-server)
	// 하지만 만약 처리 중 html error page가 발생한다면 UnknownContentTypeException이 발생하여 예외를 해결할 수 없음.
	// ref: https://github.com/spring-projects/spring-security/issues/17036
	// 요런 메타데이터에 저 엔드포인트를 제공하는 건 표준임. 근데, oauth만 지원하면 OAuth2 엔드포인트만 제공하는게 맞음.
	// 그리고 나머지 OAuth2는 제공하는데 OCID를 제공하지 않는 경우, OCID 주소에 접근했을 떄의 처리에 대한건 따로 명세하진 않은거 같음
	// (이건 뇌피셜인데 아마 그렇겠지 하위호환 문제도 있고)
	// 그래서 이런 인증을 처리하는 클라이언트(Spring Security OAuth Client 모듈)에서 지원하지 않는 엔드포인트로 접근 시 적절하게 대응할 역할이 있음.
	public static ClientRegistration.Builder fromIssuerLocation(String issuer) {
		Assert.hasText(issuer, "issuer cannot be empty");
		var a = oidc(issuer);
		var b = oidcRfc8414(issuer);
		var c = oauth(issuer);
		return getBuilder(issuer, oidc(issuer), oidcRfc8414(issuer), oauth(issuer));
	}

	static Supplier<ClientRegistration.Builder> oidc(String issuer) {
		UriComponents uri = oidcUri(issuer);
		// @formatter:on
		return () -> {
			RequestEntity<Void> request = RequestEntity.get(uri.toUriString()).build();
			Map<String, Object> configuration = rest.exchange(request, typeReference).getBody();
			OIDCProviderMetadata metadata = parse(configuration, OIDCProviderMetadata::parse);
			ClientRegistration.Builder builder = withProviderConfiguration(metadata, issuer)
				.jwkSetUri(metadata.getJWKSetURI().toASCIIString());
			if (metadata.getUserInfoEndpointURI() != null) {
				builder.userInfoUri(metadata.getUserInfoEndpointURI().toASCIIString());
			}
			return builder;
		};
	}

	static UriComponents oidcUri(String issuer) {
		UriComponents uri = UriComponentsBuilder.fromUriString(issuer).build();
		// @formatter:off
		return UriComponentsBuilder.newInstance().uriComponents(uri)
				.replacePath(uri.getPath() + OIDC_METADATA_PATH)
				.build();
	}

	static Supplier<ClientRegistration.Builder> oidcRfc8414(String issuer) {
		UriComponents uri = oidcRfc8414Uri(issuer);
		// @formatter:on
		return getRfc8414Builder(issuer, uri);
	}

	static UriComponents oidcRfc8414Uri(String issuer) {
		UriComponents uri = UriComponentsBuilder.fromUriString(issuer).build();
		// @formatter:off
		return UriComponentsBuilder.newInstance().uriComponents(uri)
				.replacePath(OIDC_METADATA_PATH + uri.getPath())
				.build();
	}

	static Supplier<ClientRegistration.Builder> oauth(String issuer) {
		UriComponents uri = oauthUri(issuer);
		return getRfc8414Builder(issuer, uri);
	}

	static UriComponents oauthUri(String issuer) {
		UriComponents uri = UriComponentsBuilder.fromUriString(issuer).build();
		// @formatter:off
		return UriComponentsBuilder.newInstance().uriComponents(uri)
				.replacePath(OAUTH_METADATA_PATH + uri.getPath())
				.build();
		// @formatter:on
	}

	private static Supplier<ClientRegistration.Builder> getRfc8414Builder(String issuer, UriComponents uri) {
		return () -> {
			RequestEntity<Void> request = RequestEntity.get(uri.toUriString()).build();
			Map<String, Object> configuration = rest.exchange(request, typeReference).getBody();
			AuthorizationServerMetadata metadata = parse(configuration, AuthorizationServerMetadata::parse);
			ClientRegistration.Builder builder = withProviderConfiguration(metadata, issuer);
			URI jwkSetUri = metadata.getJWKSetURI();
			if (jwkSetUri != null) {
				builder.jwkSetUri(jwkSetUri.toASCIIString());
			}
			String userinfoEndpoint = (String) configuration.get("userinfo_endpoint");
			if (userinfoEndpoint != null) {
				builder.userInfoUri(userinfoEndpoint);
			}
			return builder;
		};
	}

	// 여기에서 동적 파라미터를 사용해서 요청을 처리하는데, 400 에러면 폴백(나머지 서버에 요청을 이어서 진행 후 실패)를 수행하는데
	// 첫 서버에서 인증 기능을 지원하지 않을 수 있음. 따라서 이 경우도 건너 뛰는게 적절해보임.
	// 근데 이것만 처리할지, 아니면 다른 에러도 처리해야 할지 고민중인데
	// 너무 넓게 잡는것보다는 구체적으로 처리하는게 좋아보여서 그냥 좁히면 될 듯?
	// 테스트코드 작성하고?
	// 그럼 아마 404가 아니라 2xx인데, 실제로 지원하지 않는 경우이려나? 이건 사실 그 쪽 문제긴 한데, 폴백 넣을만한 이유가 될거 같긴 함.
	// 따라서 HttpClientErrorException 뿐만 아니라 HttpClientErrorException와 UnknownContentTypeException에러가 발생할 수 있음.
	// 근데 이렇게 추상적으로 하면 좀 그러니까 요소를 나누면 좋긴 할 듯?
	// 근데 흠... 폴백이 중요한게 아니라, 대부분 둘 중 하나만 지원하는데?
	// 그러면 순서를 지정해서 커스텀 가능해게 해줘야 할까? 그러면 몇몇 엔드포인트는 본인이 제거해서 쓸 수 있을거 같은데?
	// 근데 그게 흠... 사용자들이 적절하게 해결할 때 쓸 수 있나? 에러 메서지에 추가해주면 될거 같긴 한데, 이런 식으로 해결해야 한다는 것도 좀 그렇긴 함.
	// 그래도 요소 정의하는게 있으면 이런 중복 호출을 막을 수 있어서 효율적이지 않나? -> 해봤자 얼마나 효율적임?
	// 굳이 폴백 아니여도 실패하긴 할거임. 가장 중요한 문제는 폴벡이 아니라 순서가 고정되어있는데, 유효한게 뒤 데이터인 상태인데 앞 단계에서 무조건 에러가 나는 상황이 생길 수도 있다는거임.
	// 그걸 해결하는게 중요함. 폴백 생기는 순간부터 문제가 되는거임.
	@SafeVarargs
	private static ClientRegistration.Builder getBuilder(String issuer,
			Supplier<ClientRegistration.Builder>... suppliers) {
		String errorMessage = "Unable to resolve Configuration with the provided Issuer of \"" + issuer + "\"";
		List<String> errors = new ArrayList<>();
		for (Supplier<ClientRegistration.Builder> supplier : suppliers) {
			try {
				return supplier.get();
			}
			catch (HttpClientErrorException ex) {
				if (!ex.getStatusCode().is4xxClientError()) {
					throw ex;
				}
				errors.add(ex.getMessage());
				// else try another endpoint
			}
			catch (IllegalArgumentException | IllegalStateException ex) {
				throw ex;
			}
			catch (RuntimeException ex) {
				throw new IllegalArgumentException(errorMessage, ex);
			}
		}
		if (!errors.isEmpty()) {
			throw new IllegalArgumentException(errorMessage + ", errors: " + errors);
		}
		throw new IllegalArgumentException(errorMessage);
	}

	private static <T> T parse(Map<String, Object> body, ThrowingFunction<JSONObject, T, ParseException> parser) {
		try {
			return parser.apply(new JSONObject(body));
		}
		catch (ParseException ex) {
			throw new RuntimeException(ex);
		}
	}

	private static ClientRegistration.Builder withProviderConfiguration(AuthorizationServerMetadata metadata,
			String issuer) {
		String metadataIssuer = metadata.getIssuer().getValue();
		Assert.state(issuer.equals(metadataIssuer),
				() -> "The Issuer \"" + metadataIssuer + "\" provided in the configuration metadata did "
						+ "not match the requested issuer \"" + issuer + "\"");
		String name = URI.create(issuer).getHost();
		ClientAuthenticationMethod method = getClientAuthenticationMethod(metadata.getTokenEndpointAuthMethods());
		Map<String, Object> configurationMetadata = new LinkedHashMap<>(metadata.toJSONObject());
		// @formatter:off
		return ClientRegistration.withRegistrationId(name)
				.userNameAttributeName(IdTokenClaimNames.SUB)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.clientAuthenticationMethod(method)
				.redirectUri("{baseUrl}/{action}/oauth2/code/{registrationId}")
				.authorizationUri((metadata.getAuthorizationEndpointURI() != null) ? metadata.getAuthorizationEndpointURI().toASCIIString() : null)
				.providerConfigurationMetadata(configurationMetadata)
				.tokenUri(metadata.getTokenEndpointURI().toASCIIString())
				.issuerUri(issuer)
				.clientName(issuer);
		// @formatter:on
	}

	private static ClientAuthenticationMethod getClientAuthenticationMethod(
			List<com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod> metadataAuthMethods) {
		if (metadataAuthMethods == null || metadataAuthMethods
			.contains(com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_BASIC)) {
			// If null, the default includes client_secret_basic
			return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
		}
		if (metadataAuthMethods.contains(com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_POST)) {
			return ClientAuthenticationMethod.CLIENT_SECRET_POST;
		}
		if (metadataAuthMethods.contains(com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.NONE)) {
			return ClientAuthenticationMethod.NONE;
		}
		return null;
	}

	private interface ThrowingFunction<S, T, E extends Throwable> {

		T apply(S src) throws E;

	}

}
