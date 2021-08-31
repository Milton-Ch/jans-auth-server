/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.as.client.model;

import io.jans.as.client.util.ClientUtil;
import io.jans.as.model.crypto.AbstractCryptoProvider;
import io.jans.as.model.crypto.signature.AsymmetricSignatureAlgorithm;
import io.jans.as.model.crypto.signature.SignatureAlgorithm;
import io.jans.as.model.exception.InvalidJwtException;
import io.jans.as.model.jwk.JSONWebKey;
import io.jans.as.model.jwt.JwtHeader;
import io.jans.as.model.jwt.JwtType;
import io.jans.as.model.util.Base64Util;
import io.jans.as.model.util.JwtUtil;
import io.jans.as.model.util.Util;
import org.apache.commons.lang.StringUtils;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Date;
import java.util.UUID;

import static io.jans.as.model.jwt.DPoPJwtPayloadParam.*;

/**
 * @author Javier Rojas Blum
 * @version August 31, 2021
 */
public class DPoP {

    // Header
    /**
     * Type header dpop+jwt
     */
    private final JwtType type = JwtType.DPOP_PLUS_JWT;
    /**
     * Digital signature algorithm identifier (Asymmetric Algorithm, must not be none).
     */
    private SignatureAlgorithm signatureAlgorithm;
    /**
     * The public key chosen by the client, in JWK format.
     * Must not contain the private key.
     */
    private JSONWebKey jwk;

    // Payload
    /**
     * Unique identifier for the DPoP proof JWT.
     * The value must be assigned such that there is a negligible probability that the same value will be assigned
     * to any other DPoP proof used in the same context during the time window of validity.
     */
    private String jti;
    /**
     * The HTTP method for the request to which the JWT is attached.
     */
    private String htm;
    /**
     * The HTTP URI used for the request, without query and fragment parts.
     */
    private String htu;
    /**
     * Time at which the JWT was created.
     */
    private Integer iat;
    /**
     * Hash of the access token. Required when the DPoP proof is used in conjunction with the presentation of an
     * access token.
     */
    private String ath;

    // Signature Key
    private AbstractCryptoProvider cryptoProvider;

    public DPoP(AsymmetricSignatureAlgorithm asymmetricSignatureAlgorithm, JSONWebKey jwk, String jti, String htm, String htu,
                AbstractCryptoProvider cryptoProvider) {
        this(asymmetricSignatureAlgorithm, jwk, jti, htm, htu, new Date(), null, cryptoProvider);
    }

    public DPoP(AsymmetricSignatureAlgorithm asymmetricSignatureAlgorithm, JSONWebKey jwk, String jti, String htm, String htu,
                String accessTokenHash, AbstractCryptoProvider cryptoProvider) {
        this(asymmetricSignatureAlgorithm, jwk, jti, htm, htu, new Date(), accessTokenHash, cryptoProvider);
    }

    public DPoP(AsymmetricSignatureAlgorithm asymmetricSignatureAlgorithm, JSONWebKey jwk, String jti, String htm, String htu,
                Date issuedAt, String accessTokenHash, AbstractCryptoProvider cryptoProvider) {
        this.signatureAlgorithm = SignatureAlgorithm.fromString(asymmetricSignatureAlgorithm.getParamName());
        this.jwk = jwk;

        this.jti = jti;
        this.htm = htm;
        this.htu = htu;
        this.iat = Util.getNumberOfSecondFromNow(issuedAt);
        this.ath = accessTokenHash;

        this.cryptoProvider = cryptoProvider;
    }

    public static String generateJti() {
        String jti = null;

        try {
            String guid = UUID.randomUUID().toString();
            byte[] sig = Util.getBytes(guid);
            jti = Base64Util.base64urlencode(sig);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return jti;
    }

    public static String generateAccessTokenHash(String accessToken) {
        String accessTokenHash = null;

        try {
            final byte[] digest = JwtUtil.getMessageDigestSHA256(accessToken);

            if (digest != null) {
                accessTokenHash = Base64Util.base64urlencode(digest);
            }
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }

        return accessTokenHash;
    }

    public JwtType getType() {
        return type;
    }

    public AsymmetricSignatureAlgorithm getSignatureAlgorithm() {
        return AsymmetricSignatureAlgorithm.fromString(signatureAlgorithm.getName());
    }

    public void setSignatureAlgorithm(AsymmetricSignatureAlgorithm asymmetricSignatureAlgorithm) {
        this.signatureAlgorithm = SignatureAlgorithm.fromString(asymmetricSignatureAlgorithm.getParamName());
    }

    public JSONWebKey getJwk() {
        return jwk;
    }

    public void setJwk(JSONWebKey jwk) {
        this.jwk = jwk;
    }

    public String getJti() {
        return jti;
    }

    public void setJti(String jti) {
        this.jti = jti;
    }

    public String getHtm() {
        return htm;
    }

    public void setHtm(String htm) {
        this.htm = htm;
    }

    public String getHtu() {
        return htu;
    }

    public void setHtu(String htu) {
        this.htu = htu;
    }

    public Integer getIat() {
        return iat;
    }

    public void setIat(Integer iat) {
        this.iat = iat;
    }

    public String getAth() {
        return ath;
    }

    public AbstractCryptoProvider getCryptoProvider() {
        return cryptoProvider;
    }

    public void setCryptoProvider(AbstractCryptoProvider cryptoProvider) {
        this.cryptoProvider = cryptoProvider;
    }

    public String getEncodedJwt() throws Exception {
        String encodedJwt = null;

        // Check header params:
        if (type != JwtType.DPOP_PLUS_JWT) {
            throw new InvalidJwtException("Type (typ) value must be dpop+jwt");
        }
        if (signatureAlgorithm == null) {
            throw new InvalidJwtException("Algorithm (alg) must be an asymmetric algorithm");
        }
        if (jwk == null) {
            throw new InvalidJwtException("JWK (jwk) is required");
        }

        // Check Payload params:
        if (StringUtils.isBlank(jti)) {
            throw new InvalidJwtException("The JWT Unique identifier (jti) is required");
        }
        if (StringUtils.isBlank(htm)) {
            throw new InvalidJwtException("The HTTP method (htm) is required");
        }
        if (StringUtils.isBlank(htu)) {
            throw new InvalidJwtException("The HTTP URI (htu) is required");
        }
        if (iat == null || iat <= 0) {
            throw new InvalidJwtException("The issued at (iat) is required");
        }

        // TODO: Validate JWK

        if (cryptoProvider == null) {
            throw new Exception("The Crypto Provider cannot be null.");
        }

        JSONObject headerJsonObject = headerToJSONObject();
        JSONObject payloadJsonObject = payloadToJSONObject();

        String headerString = ClientUtil.toPrettyJson(headerJsonObject);
        String payloadString = ClientUtil.toPrettyJson(payloadJsonObject);

        String encodedHeader = Base64Util.base64urlencode(headerString.getBytes(Util.UTF8_STRING_ENCODING));
        String encodedPayload = Base64Util.base64urlencode(payloadString.getBytes(Util.UTF8_STRING_ENCODING));

        String signingInput = encodedHeader + "." + encodedPayload;
        String encodedSignature = cryptoProvider.sign(signingInput, null, null, signatureAlgorithm);

        encodedJwt = encodedHeader + "." + encodedPayload + "." + encodedSignature;

        return encodedJwt;
    }

    protected JSONObject headerToJSONObject() throws InvalidJwtException {
        JwtHeader jwtHeader = new JwtHeader();

        jwtHeader.setType(type);
        jwtHeader.setAlgorithm(signatureAlgorithm);
        // TODO: JWK

        return jwtHeader.toJsonObject();
    }

    protected JSONObject payloadToJSONObject() throws JSONException {
        JSONObject obj = new JSONObject();

        obj.put(JTI, jti);
        obj.put(HTM, htm);
        obj.put(HTU, htu);
        obj.put(IAT, iat);

        if (StringUtils.isNotBlank(ath)) {
            obj.put(ATH, ath);
        }

        return obj;
    }
}
