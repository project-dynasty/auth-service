package com.projectdynasty.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.Claim;
import com.projectdynasty.AuthService;
import com.projectdynasty.payload.Token;
import com.projectdynasty.payload.request.AuthStatus;
import com.projectdynasty.payload.response.TokenResponse;
import com.projectdynasty.security.services.UserDetailsImpl;
import de.alexanderwodarz.code.log.Level;
import de.alexanderwodarz.code.log.Log;
import de.alexanderwodarz.code.web.rest.RequestData;
import de.alexanderwodarz.code.web.rest.authentication.Authentication;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class JwtUtils {

    private final String secret = AuthService.CONFIG.get("jwt", AuthService.Jwt.class).getKey();
    private final String refreshSecret = AuthService.CONFIG.get("jwt", AuthService.Jwt.class).getRefreshKey();
    private final int jwtExpirationMs = AuthService.CONFIG.get("jwt", AuthService.Jwt.class).getExpire() * 1000;
    private final int jwtRememberMs = AuthService.CONFIG.get("jwt", AuthService.Jwt.class).getExpireRefresh() * 1000;

    public TokenResponse generateJwtToken(Authentication authentication, AuthStatus authStatus) {
        Token token = Token.create((UserDetailsImpl) authentication, authStatus);
        return new TokenResponse(
                token.generateToken(),
                token.generateRefreshToken()
        );
    }

    public String generateRefreshToken(String subject, List<Map<String, Object>> permissionMap, boolean mobile, long deviceId, boolean otp) {
        Date expire = new Date(System.currentTimeMillis() + jwtRememberMs);
        Algorithm algorithm = Algorithm.HMAC256(refreshSecret);

        return JWT.create().withIssuer(AuthService.CONFIG.get("jwt", AuthService.Jwt.class).getIss())
                .withExpiresAt(expire)
                .withSubject(subject)
                .withClaim("permissions", permissionMap)
                .withClaim("mobile", mobile)
                .withClaim("deviceId", deviceId)
                .withClaim("otp", otp)
                .withClaim("refresh", true)
                .withIssuedAt(new Date()).sign(algorithm);
    }

    public TokenResponse fromRefreshToken(String token) {
        if (!validateJwtRefreshToken(token))
            return null;
        Date expire = new Date(System.currentTimeMillis() + jwtExpirationMs);
        Algorithm algorithm = Algorithm.HMAC256(secret);
        // create timestamp

        String subject = getRefreshSubject(token);
        List<Map<String, Object>> permissionMap = getRefreshClaim(token, "permissions").asList((Class<Map<String, Object>>) (Class<?>) Map.class);
        boolean mobile = getRefreshClaim(token, "mobile").asBoolean();
        long deviceId = getRefreshClaim(token, "deviceId").asLong();
        boolean otp = getRefreshClaim(token, "otp").asBoolean();

        return new TokenResponse(JWT.create().withIssuer(AuthService.CONFIG.get("jwt", AuthService.Jwt.class).getIss())
                .withExpiresAt(expire)
                .withSubject(subject)
                .withClaim("permissions", permissionMap)
                .withClaim("mobile", mobile)
                .withClaim("deviceId", deviceId)
                .withClaim("otp", otp)
                .withIssuedAt(new Date()).sign(algorithm),
                generateRefreshToken(subject, permissionMap, mobile, deviceId, otp));
    }

    public String generateAuthToken(long userId) {
        Algorithm algorithm = Algorithm.HMAC256(secret);
        Date expire = new Date((new Date()).getTime() + (1000 * 60 * 5));
        return JWT.create().withIssuer(AuthService.CONFIG.get("jwt", AuthService.Jwt.class).getIss())
                .withExpiresAt(expire)
                .withSubject(String.valueOf(userId))
                .withClaim("otp", true)
                .withIssuedAt(new Date()).sign(algorithm);
    }

    public boolean isMobileRequest(RequestData data) {
        String jwt = AuthTokenFilter.parseJwt(data.getHeader("authorization"));
        try {
            return AuthService.VERIFIER.verify(jwt).getClaim("mobile").asBoolean();
        } catch (TokenExpiredException | SignatureVerificationException e) {
            return false;
        }
    }

    public long getDeviceId(RequestData data) {
        String jwt = AuthTokenFilter.parseJwt(data.getHeader("authorization"));
        try {
            return AuthService.VERIFIER.verify(jwt).getClaim("deviceId").asLong();
        } catch (TokenExpiredException | SignatureVerificationException e) {
            return 0L;
        }
    }

    public String getSubject(String token) {
        try {
            return AuthService.VERIFIER.verify(token).getSubject();
        } catch (TokenExpiredException | SignatureVerificationException e) {
            return null;
        }
    }

    public String getRefreshSubject(String token) {
        try {
            return AuthService.REFRESH_VERIFIER.verify(token).getSubject();
        } catch (TokenExpiredException | SignatureVerificationException e) {
            return null;
        }
    }

    public boolean validateJwtToken(String authToken) {
        try {
            AuthService.VERIFIER.verify(authToken);
            return getClaim(authToken, "refresh").isMissing();
        } catch (SignatureVerificationException | JWTDecodeException |
                 TokenExpiredException e) {
            Log.log(e.getMessage(), Level.ERROR);
        }
        return false;
    }

    public HashMap<String, String> generatePushAuthorizationToken() {
        Algorithm algorithm = Algorithm.HMAC256(secret);
        Date expire = new Date((new Date()).getTime() + (1000 * 60));
        HashMap<String, String> headers = new HashMap<>();
        String auth = JWT.create().withIssuer(AuthService.CONFIG.get("jwt", AuthService.Jwt.class).getIss())
                .withExpiresAt(expire)
                .sign(algorithm);
        headers.put("Authorization", "Bearer " + auth);
        return headers;
    }

    public boolean validateJwtRefreshToken(String authToken) {
        try {
            AuthService.REFRESH_VERIFIER.verify(authToken);
            return true;
        } catch (SignatureVerificationException | JWTDecodeException |
                 TokenExpiredException e) {
            Log.log(e.getMessage(), Level.ERROR);
        }
        return false;
    }

    public Claim getClaim(String token, String claim) {
        try {
            return AuthService.VERIFIER.verify(token).getClaim(claim);
        } catch (TokenExpiredException e) {
            return null;
        }
    }

    public Claim getRefreshClaim(String token, String claim) {
        try {
            return AuthService.REFRESH_VERIFIER.verify(token).getClaim(claim);
        } catch (TokenExpiredException e) {
            return null;
        }
    }
}
