package com.jwt.test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.URL;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.Base64.Decoder;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

import javax.net.ssl.HttpsURLConnection;
import javax.servlet.http.HttpServletRequest;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

public class AzureJWTValidation {
	private KeyBean key;
	
	public void initIt() throws IOException {
		this.key = discoveryKeys("https://login.microsoftonline.com/<tenant_id>/v2.0").getKeys().get(0);
		System.out.println("Inspection token key's populated :" + new Date());
	}

	public enum API_CONSTANTS {
		BEARER("Bearer"), AUTHORIZATION("Authorization"), USER_NAME("UserName");

		private String name;

		API_CONSTANTS(String name) {
			this.setName(name);
		}

		public String getName() {
			return name;
		}

		public void setName(String name) {
			this.name = name;
		}
	}

	public static final String NULL_STRING = "null";

	public String parseValidateToken(final String authToken) throws TokenException {
		if (authToken == null || NULL_STRING.equalsIgnoreCase(authToken)) {
			throw new TokenException(401, "Invalid Authorization Bearer token");
		}
		final Map<String, Object> mapTokenComponents = getTokenComponents(authToken);
		/*
		 * Verify Header
		 */
		@SuppressWarnings("unchecked")
		final Map<String, Object> tokenHeader = (Map<String, Object>) mapTokenComponents.get("header");
		String kid = (String) tokenHeader.get("kid");
		if (!this.key.getKeyIdentifier().equals(kid)) {
			System.out.println("Invalid Header information with key --> " + kid);
			throw new TokenException(400, "Invalid Header");
		}
		/* Validate Claims with signed key */
		PublicKey pubKeyNew;
		Claims claims = null;
		try {
			byte[] modulusBytes = Base64.getUrlDecoder().decode(this.key.getModulusByte());
			byte[] exponentBytes = Base64.getUrlDecoder().decode(this.key.getExponentByte());
			BigInteger modulusInt = new BigInteger(1, modulusBytes);
			BigInteger exponentInt = new BigInteger(1, exponentBytes);
			KeySpec publicSpec = null;
			KeyFactory keyFactory = KeyFactory.getInstance(this.key.getKeyType());
			switch (this.key.getKeyType()) {
			case "RSA":
				publicSpec = new RSAPublicKeySpec(modulusInt, exponentInt);
				break;
			default:
				throw new TokenException(401, "No implemenetation found for " + this.key.getKeyType());
			}
			pubKeyNew = keyFactory.generatePublic(publicSpec);
			claims = Jwts.parser().setSigningKey(pubKeyNew).parseClaimsJws(authToken).getBody();
			System.out.println("Expiration Date:: " + claims.getExpiration().toString());
			System.out.println("Issued Date:: " + claims.getIssuedAt().toString());
			System.out.println("Issuer:: " + claims.getIssuer());
			System.out.println("Audience:: " + claims.getAudience());
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new TokenException(401, "Invalid supplied key : " + e.getMessage());
		}
		if (claims == null || !"test".equals(claims.getAudience())) {
			System.out.println("Not valid Application Id - ");
			throw new TokenException(500, "Not valid Application Id");
		}
		return "success";
	}

	/**
	 * Verify JWT token with all three important section i.e Header, Payload,
	 * Signature
	 * 
	 * @param token
	 * @return
	 * @throws TokenException
	 */
	private Map<String, Object> getTokenComponents(String token) throws TokenException {
		final Decoder decoder = Base64.getDecoder();
		final StringTokenizer tokenizer = new StringTokenizer(token, ".");
		int i = 0;
		Map<String, Object> tokenHeader = new HashMap<String, Object>();
		Map<String, Object> tokenBody = new HashMap<String, Object>();
		String signatureJws = "";
		final Map<String, Object> tokenMapParts = new HashMap<String, Object>();
		// (1) DECODE THE 3 PARTS OF THE JWT TOKEN
		try {
			while (tokenizer.hasMoreElements()) {
				if (i == 0) {
					tokenHeader = string2JSONMap(new String(decoder.decode(tokenizer.nextToken())));
				} else if (i == 1) {
					tokenBody = string2JSONMap(new String(decoder.decode(tokenizer.nextToken())));
				} else {
					signatureJws = new String(tokenizer.nextToken());
				}
				i++;
			}
		} catch (IOException e) {
			System.out.println("Invalid token " + e);
			throw new TokenException(401, e.getMessage());
		}
		// (1.1) THE 3 PARTS OF THE TOKEN SHOULD BE IN PLACE
		if (tokenHeader == null || tokenBody == null || signatureJws == null || tokenHeader.isEmpty()
				|| tokenBody.isEmpty() || signatureJws.isEmpty()) {
			System.out.println("Invalid token(tokenHeader,tokenBody,signatureJws) ");
			throw new TokenException(401, "Invalid Token");
		}
		tokenMapParts.put("header", tokenHeader);
		tokenMapParts.put("body", tokenBody);
		tokenMapParts.put("signature", signatureJws);
		return tokenMapParts;
	}

	/**
	 * Load JWKS information.
	 * 
	 * @param keysURL
	 * @return
	 * @throws IOException
	 */
	public OpenIdKeysBean discoveryKeys(String keysURL) throws IOException {
		OpenIdKeysBean openIdKeysBean = new OpenIdKeysBean();
		final URL url = new URL(keysURL);
		final HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
		if (con != null) {
			BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream()));
			String input;
			StringBuilder builder = new StringBuilder();
			while ((input = br.readLine()) != null) {
				builder.append(input);
			}
			br.close();
			ObjectMapper mapper = new ObjectMapper();
			mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
			openIdKeysBean = mapper.readValue(builder.toString(), OpenIdKeysBean.class);
		}
		return openIdKeysBean;
	}

	public Map<String, Object> string2JSONMap(String json)
			throws JsonParseException, JsonMappingException, IOException {
		ObjectMapper mapper = new ObjectMapper();
		// convert JSON string to Map
		return mapper.readValue(json, new TypeReference<Map<String, Object>>() {
		});
	}

	public String getAuthToken(HttpServletRequest request) throws TokenException {
		String jwtToken = null;
		String requestHeader = request.getHeader(API_CONSTANTS.AUTHORIZATION.getName());
		if (requestHeader != null && !requestHeader.startsWith(API_CONSTANTS.BEARER.getName())) {
			throw new TokenException(401, "Invalid Authorization Bearer token");
		} else if (requestHeader != null) {
			jwtToken = requestHeader.substring(7);
		}
		return jwtToken;
	}

}
