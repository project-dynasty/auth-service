package com.projectdynasty.payload;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.projectdynasty.AuthService;
import com.projectdynasty.models.AccountData;
import com.projectdynasty.models.TokenData;
import com.projectdynasty.models.permission.GroupData;
import com.projectdynasty.payload.request.AuthStatus;
import com.projectdynasty.payload.response.user.permission.PermissionResponse;
import com.projectdynasty.security.services.UserDetailsImpl;
import de.alexanderwodarz.code.JavaCore;
import lombok.RequiredArgsConstructor;

import java.util.*;
import java.util.stream.Collectors;

@RequiredArgsConstructor
public class Token {

    private final String secret = AuthService.CONFIG.get("jwt", AuthService.Jwt.class).getKey();
    private final String refreshSecret = AuthService.CONFIG.get("jwt", AuthService.Jwt.class).getRefreshKey();
    private final int jwtExpirationMs = AuthService.CONFIG.get("jwt", AuthService.Jwt.class).getExpire() * 1000;
    private final int jwtExpireRefresh = AuthService.CONFIG.get("jwt", AuthService.Jwt.class).getExpireRefresh() * 1000;
    private final int jwtMobileExpireRefresh = AuthService.CONFIG.get("jwt", AuthService.Jwt.class).getExpireMobileRefresh() * 1000;

    private final TokenData tokenData;

    public static Token get(String id) {
        TokenData filter = (TokenData) AuthService.DATABASE.getTable(TokenData.class).query().addParameter("id", id).executeOne();
        if (filter == null)
            return null;
        return new Token(filter);
    }

    public static Token create(UserDetailsImpl userDetails, AuthStatus authStatus) {
        TokenData data = AuthService.DATABASE.getTable(TokenData.class);
        data.userId = userDetails.getId();
        data.id = JavaCore.getRandomString(32);
        data.created = System.currentTimeMillis() / 1000;
        data.last = System.currentTimeMillis() / 1000;
        data.challenge = authStatus.isChallengeToken();
        data.mobile = authStatus.isMobile();
        data.deviceId = authStatus.getDeviceId();
        data.expires = System.currentTimeMillis() / 1000 + AuthService.CONFIG.get("jwt", AuthService.Jwt.class).getExpireRefresh() * 1000L;
        data.insert();
        return new Token(data);
    }

    public String generateToken() {
        UserDetailsImpl userDetails = UserDetailsImpl.build((AccountData) AuthService.DATABASE.getTable(AccountData.class).query().addParameter("user_id", getUserId()).executeOne());

        Date expire = new Date(System.currentTimeMillis() + jwtExpirationMs);
        Algorithm algorithm = Algorithm.HMAC256(secret);

        return JWT.create().withIssuer(AuthService.CONFIG.get("jwt", AuthService.Jwt.class).getIss())
                .withExpiresAt(expire)
                .withSubject(userDetails.getUsername())
                .withClaim("permissions", generatePermissionMap(userDetails))
                .withClaim("mobile", isMobile())
                .withClaim("deviceId", getDeviceId())
                .withClaim("otp", isOtp())
                .withClaim("id", userDetails.getId())
                .withClaim("challenge", isChallenge())
                .withKeyId(getId())
                .withIssuedAt(new Date()).sign(algorithm);
    }

    public String generateRefreshToken() {
        Algorithm algorithm = Algorithm.HMAC256(refreshSecret);
        Date expire = new Date(System.currentTimeMillis() + (isMobile() ? jwtMobileExpireRefresh : jwtExpireRefresh));

        AuthService.DATABASE.update("UPDATE token_data SET expires='" + expire.getTime() / 1000 + "' WHERE id='" + getId() + "';", null);
        return JWT.create().withIssuer(AuthService.CONFIG.get("jwt", AuthService.Jwt.class).getIss())
                .withExpiresAt(expire)
                .withClaim("refresh", true)
                .withKeyId(getId())
                .withIssuedAt(new Date()).sign(algorithm);
    }

    private List<Map<String, Object>> generatePermissionMap(UserDetailsImpl userDetails) {
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
                if (permission.isNegate()) {
                    permissionMap.add(new HashMap<>() {{
                        put("perm", permission.getPermission());
                        put("negate", permission.isNegate());
                        put("value", permission.getValue());
                    }});
                }
            }
        }
        return permissionMap;
    }

    public String getId() {
        return tokenData.id;
    }

    public long getUserId() {
        return tokenData.userId;
    }

    public long getCreated() {
        return tokenData.created;
    }

    public boolean isMobile() {
        return tokenData.mobile;
    }

    public boolean isChallenge() {
        return tokenData.challenge;
    }

    public boolean isOtp() {
        return tokenData.otp;
    }

    public long getDeviceId() {
        return tokenData.deviceId;
    }

    public long getLast() {
        return tokenData.last;
    }

    public long getExpires() {
        return tokenData.expires;
    }

}
