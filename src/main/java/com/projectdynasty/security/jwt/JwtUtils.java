package com.projectdynasty.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.projectdynasty.AuthService;
import com.projectdynasty.models.permission.GroupData;
import com.projectdynasty.payload.request.AuthStatus;
import com.projectdynasty.payload.response.user.permission.PermissionResponse;
import com.projectdynasty.security.services.UserDetailsImpl;
import de.alexanderwodarz.code.log.Level;
import de.alexanderwodarz.code.log.Log;
import de.alexanderwodarz.code.web.rest.authentication.Authentication;

import java.util.*;
import java.util.stream.Collectors;

public class JwtUtils {

    private final String secret = AuthService.CONFIG.get("jwt", AuthService.Jwt.class).getKey();
    private final int jwtExpirationMs = AuthService.CONFIG.get("jwt", AuthService.Jwt.class).getExpire() * 1000;
    private final int jwtRememberMs = AuthService.CONFIG.get("jwt", AuthService.Jwt.class).getExpireRefresh() * 1000;

    public String generateJwtToken(Authentication authentication, AuthStatus authStatus) {
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication;

        Date expire = new Date(System.currentTimeMillis() + (authStatus.isRememberMe() ? jwtRememberMs : jwtExpirationMs));
        Algorithm algorithm = Algorithm.HMAC256(secret);

        List<PermissionResponse> permissions = new ArrayList<>();
        for (GroupData groupData : userDetails.getRoles())
            permissions.addAll(userDetails.toGroupPermissionResponse(groupData));
        permissions.addAll(userDetails.toPermissionResponse());
        List<Map<String, Object>> permissionMap = permissions.stream().map(permission -> new HashMap<String, Object>() {{
            put("perm", permission.getPermission());
            put("negate", permission.isNegate());
            put("value", permission.getValue());
        }}).collect(Collectors.toList());

        if (permissions.stream().anyMatch(permissionResponse -> permissionResponse.getPermission().equals("*"))) {
            permissionMap = new ArrayList<>();
            permissionMap.add(new HashMap<>() {{
                put("perm", "*");
                put("negate", false);
                put("value", 0);
            }});
            for (PermissionResponse permission : permissions) {
                if(permission.isNegate()) {
                    permissionMap.add(new HashMap<>() {{
                        put("perm", permission.getPermission());
                        put("negate", permission.isNegate());
                        put("value", permission.getValue());
                    }});
                }
            }
        }

        return JWT.create().withIssuer(AuthService.CONFIG.get("jwt", AuthService.Jwt.class).getIss())
                .withExpiresAt(expire)
                .withSubject(userDetails.getUsername())
                .withClaim("permissions", permissionMap)
                .withClaim("mobile", authStatus.isMobile())
                .withClaim("deviceId", authStatus.getDeviceId())
                .withIssuedAt(new Date()).sign(algorithm);
    }

    public String getSubject(String token) {
        try {
            return AuthService.VERIFIER.verify(token).getSubject();
        } catch (TokenExpiredException e) {
            return null;
        }
    }

    public boolean validateJwtToken(String authToken) {
        try {
            AuthService.VERIFIER.verify(authToken);
            return true;
        } catch (SignatureVerificationException | JWTDecodeException |
                 TokenExpiredException e) {
            Log.log(e.getMessage(), Level.ERROR);
        }
        return false;
    }
}
