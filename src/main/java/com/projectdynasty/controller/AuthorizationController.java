package com.projectdynasty.controller;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.gson.Gson;
import com.projectdynasty.AuthService;
import com.projectdynasty.PushNotification;
import com.projectdynasty.models.AccountData;
import com.projectdynasty.models.AuthenticationData;
import com.projectdynasty.payload.Challenge;
import com.projectdynasty.payload.Device;
import com.projectdynasty.payload.Token;
import com.projectdynasty.payload.request.AuthStatus;
import com.projectdynasty.payload.request.SigninRequest;
import com.projectdynasty.payload.request.SolveChallengeRequest;
import com.projectdynasty.payload.request.TwoFARequest;
import com.projectdynasty.payload.response.TokenResponse;
import com.projectdynasty.security.services.UserDetailsImpl;
import de.alexanderwodarz.code.web.StatusCode;
import de.alexanderwodarz.code.web.rest.RequestData;
import de.alexanderwodarz.code.web.rest.ResponseData;
import de.alexanderwodarz.code.web.rest.annotation.*;
import de.alexanderwodarz.code.web.rest.authentication.AuthenticationManager;
import org.json.JSONObject;
import org.mindrot.jbcrypt.BCrypt;

import java.util.*;

@RestController(produces = "application/json")
public class AuthorizationController {

    private static final String password = "$2a$10$EEIui2SVbvqRU.SaA8amheB72OlbH6dxTvMABPZPcjURzXIg2R0pC";

    private static final Map<Long, SigninRequest> signinRequests = new HashMap<>();
    private static final Map<String, AuthStatus> permitted = new HashMap<>();

    private static final List<String> refreshToken = new ArrayList<>();

    @RestRequest(path = "/challenge", method = "PUT")
    public static ResponseData createChallenge() {
        Challenge challenge = Challenge.create();
        return new ResponseData(challenge.build().toString(), StatusCode.OK);
    }

    @RestRequest(path = "/challenge/claim", method = "POST")
    public static ResponseData claimChallenge(@RequestBody String challengeSolve) {
        if (AuthenticationManager.getAuthentication() == null)
            return new ResponseData("{}", StatusCode.UNAUTHORIZED);
        SolveChallengeRequest solveChallenge = new Gson().fromJson(challengeSolve, SolveChallengeRequest.class);
        Challenge challenge = Challenge.getByChallenge(solveChallenge.getChallenge());
        if (challenge == null)
            return new ResponseData("{}", StatusCode.NOT_FOUND);
        if (!challenge.getStatus().equals("new"))
            return new ResponseData("{}", StatusCode.ALREADY_REPORTED);
        if (!challenge.isConnected())
            return new ResponseData("{}", 425);
        UserDetailsImpl userDetails = (UserDetailsImpl) AuthenticationManager.getAuthentication();
        challenge.setUserId(userDetails.getId());
        challenge.setStatus("claim");
        challenge.getConnectedClient().send(new JSONObject().put("name", userDetails.getUsername()).put("type", "claim").put("avatar", userDetails.getAvatar()).toString());
        return new ResponseData("{}", StatusCode.OK);
    }

    @RestRequest(path = "/challenge/unclaim", method = "POST")
    public static ResponseData unclaimChallenge(@RequestBody String challengeSolve) {
        if (AuthenticationManager.getAuthentication() == null)
            return new ResponseData("{}", StatusCode.UNAUTHORIZED);
        SolveChallengeRequest solveChallenge = new Gson().fromJson(challengeSolve, SolveChallengeRequest.class);
        Challenge challenge = Challenge.getByChallenge(solveChallenge.getChallenge());
        if (challenge == null)
            return new ResponseData("{}", StatusCode.NOT_FOUND);
        UserDetailsImpl userDetails = (UserDetailsImpl) AuthenticationManager.getAuthentication();
        if (challenge.getUserId() != userDetails.getId())
            return new ResponseData("{}", StatusCode.UNAUTHORIZED);
        if (!challenge.getStatus().equals("claim"))
            return new ResponseData("{}", StatusCode.BAD_REQUEST);
        if (!challenge.isConnected())
            return new ResponseData("{}", 425);
        challenge.setUserId(0);
        challenge.setStatus("new");
        challenge.getConnectedClient().send(new JSONObject().put("type", "unclaim").toString());
        return new ResponseData("{}", StatusCode.OK);
    }

    @RestRequest(path = "/challenge/solve", method = "POST")
    public static ResponseData solveChallenge(@RequestBody String challengeSolve) {
        if (AuthenticationManager.getAuthentication() == null)
            return new ResponseData("{}", StatusCode.UNAUTHORIZED);
        SolveChallengeRequest solveChallenge = new Gson().fromJson(challengeSolve, SolveChallengeRequest.class);
        Challenge challenge = Challenge.getByChallenge(solveChallenge.getChallenge());
        if (challenge == null || challenge.getStatus().equals("claimed"))
            return new ResponseData("{}", StatusCode.BAD_REQUEST);
        if (!challenge.isConnected())
            return new ResponseData("{}", 425);
        UserDetailsImpl userDetails = (UserDetailsImpl) AuthenticationManager.getAuthentication();
        AuthStatus status = new AuthStatus();
        status.setChallengeToken(true);
        status.setDeviceId(0);
        challenge.setStatus("solved");
        JSONObject tokens = new JSONObject(getTokens(status, userDetails.getUsername()).getBody());
        tokens.put("type", "token");
        challenge.getConnectedClient().send(tokens.toString());
        challenge.getConnectedClient().getSocket().close();
        return new ResponseData("{}", StatusCode.OK);
    }


    @RestRequest(path = "/signin", method = "POST")
    public static ResponseData signin(@RequestBody String signin, RequestData data) {
        SigninRequest signinRequest = new Gson().fromJson(signin, SigninRequest.class);
        if (signinRequest == null || signinRequest.getUsername() == null)
            return new ResponseData("{}", StatusCode.BAD_REQUEST);
        JSONObject obj = new JSONObject(signin);
        AccountData accountData = (AccountData) AuthService.DATABASE.getTable(AccountData.class).query().addParameter("username", signinRequest.getUsername()).executeOne();
        if (accountData == null)
            return new ResponseData("{\"message\": \"Username of password do not match.\"}", StatusCode.UNAUTHORIZED);

        AuthenticationData authenticationData = (AuthenticationData) AuthService.DATABASE.getTable(AuthenticationData.class).query().addParameter("user_id", accountData.userId).executeOne();
        if (authenticationData.getPassword() == null)
            return new ResponseData("{\"message\": \"This user is not completely registered yet.\"}", StatusCode.UNAUTHORIZED);
        if (!BCrypt.checkpw(signinRequest.getPassword(), authenticationData.getPassword()))
            return new ResponseData("{\"message\": \"Username of password do not match.\"}", StatusCode.UNAUTHORIZED);

        AuthStatus status = new AuthStatus();
        status.setRememberMe(signinRequest.isRememberMe());
        status.setMobile(signinRequest.getOsType() != null && signinRequest.getOsVersion() != null && signinRequest.getScreenSize() != null);
        if (status.isMobile()) {
            Device device = Device.create(data.getSocket().getInetAddress().getHostAddress(), signinRequest.getOsVersion(), signinRequest.getOsType(), signinRequest.getScreenSize(), accountData.userId);
            status.setDeviceId(device.getId());
        }

        signinRequests.put(accountData.userId, signinRequest);
        if (authenticationData.getAuthOtpMobileValue() != null && !authenticationData.getAuthOtpMobileValue().equals("")) {
            String token = AuthService.JWT_UTILS.generateAuthToken(accountData.userId);
            status.setOtp(true);
            status.setStatus("wait");
            status.setToken(token);
            status.setMobileConfirm(new Random().nextInt(1000));
            status.setFakeOne(new Random().nextInt(1000));
            status.setFakeTwo(new Random().nextInt(1000));
            status.setId(accountData.userId);
            boolean sentCode = Device.getFromUser(accountData.userId).size() > 0;
            PushNotification.trigger2fa(accountData.userId, token, status.getFakeOne() + "," + status.getMobileConfirm() + "," + status.getFakeTwo(), !obj.has("live") || !(obj.get("live") instanceof Boolean) || obj.getBoolean("live"));
            permitted.put(token, status);
            return new ResponseData("{\"token\": \"" + token + "\", \"mobile\": \"" + (sentCode ? status.getMobileConfirm() : 0) + "\", \"username\": \"" + accountData.username + "\"}", StatusCode.OK);
        }
        return getTokens(status, signinRequest.getUsername());
    }

    @RestRequest(method = "POST", path = "/mobile-auth")
    public static ResponseData authUser(RequestData request, @RequestBody String b) {
        System.out.println(b);
        JSONObject body = new JSONObject(b);
        int confirmCode = body.getInt("confirmCode");
        String token = body.getString("token");
        String auth = request.getHeader("authorization");
        if (auth == null || !auth.contains(" "))
            return new ResponseData("{}", StatusCode.BAD_REQUEST);
        auth = auth.split(" ")[1];

        if (!AuthService.VERIFIER.verify(auth).getClaim("mobile").asBoolean())
            return new ResponseData("{}", StatusCode.BAD_REQUEST);
        UserDetailsImpl userDetails = (UserDetailsImpl) AuthenticationManager.getAuthentication();
        AuthStatus status = permitted.get(token);
        if (userDetails == null || status == null)
            return new ResponseData("{}", StatusCode.BAD_REQUEST);
        if (status.getId() != userDetails.getId())
            return new ResponseData("{}", StatusCode.UNAUTHORIZED);
        if (status.getMobileConfirm() == confirmCode) {
            permitted.get(token).setStatus("ok");
            return new ResponseData("{}", StatusCode.OK);
        }
        return new ResponseData("{}", StatusCode.BAD_REQUEST);
    }

    @RestRequest(path = "/otp", method = "POST")
    public static ResponseData authenticate(@RequestBody String twoFactor) {
        TwoFARequest request = new Gson().fromJson(twoFactor, TwoFARequest.class);
        if (request.getToken() == null || !AuthService.JWT_UTILS.validateJwtToken(request.getToken()))
            return new ResponseData("{\"message\": \"Invalid token.\"}", StatusCode.UNAUTHORIZED);

        String subject = AuthService.JWT_UTILS.getSubject(request.getToken());
        if (subject == null) return new ResponseData("{}", StatusCode.UNAUTHORIZED);

        Long id;
        try {
            id = Long.parseLong(subject);
        } catch (NumberFormatException e) {
            id = AuthService.JWT_UTILS.getClaim(request.getToken(), "id").asLong();
            if (!TwoFactorController.CREATE_MAP.containsKey(id)) return new ResponseData("{}", StatusCode.UNAUTHORIZED);
        }
        AuthenticationData authData = (AuthenticationData) AuthService.DATABASE.getTable(AuthenticationData.class).query().addParameter("user_id", id).executeOne();
        if (authData == null) return new ResponseData("{}", StatusCode.UNAUTHORIZED);

        String otpValue = TwoFactorController.CREATE_MAP.containsKey(id) ? TwoFactorController.CREATE_MAP.get(id) : authData.getAuthOtpMobileValue();
        if (request.getCode().equals(AuthService.TWO_FACTOR.getTOTPCode(otpValue))) {
            if (TwoFactorController.CREATE_MAP.containsKey(id)) {
                AuthenticationData update = AuthService.DATABASE.getTable(AuthenticationData.class);
                update.authOtpMobileValue = otpValue;
                update.update(update, authData);

                TwoFactorController.CREATE_MAP.remove(id);
                signinRequests.put(id, signinRequests.get(id));
                permitted.put(request.getToken(), new AuthStatus());
            }

            if (!signinRequests.containsKey(id)) return new ResponseData("{}", StatusCode.UNAUTHORIZED);

            permitted.get(request.getToken()).setStatus("ok");
            return new ResponseData("{}", StatusCode.OK);
        }

        return new ResponseData("{}", StatusCode.UNAUTHORIZED);
    }

    @RestRequest(path = "/status", method = "POST")
    public static ResponseData getStatus(@RequestBody String body) {
        JSONObject object = new JSONObject(body);
        if (!object.has("token")) return new ResponseData("{}", StatusCode.UNAUTHORIZED);

        String token = object.getString("token");
        if (token == null) return new ResponseData("{}", StatusCode.UNAUTHORIZED);
        if (!permitted.containsKey(token)) return new ResponseData("{}", StatusCode.UNAUTHORIZED);

        AuthStatus status = permitted.get(token);
        switch (status.getStatus()) {
            case "ok": {
                SigninRequest signinRequest = signinRequests.get(status.getId());
                signinRequests.remove(status.getId());
                permitted.remove(token);
                return getTokens(status, signinRequest.getUsername());
            }
            case "wait": {
                return new ResponseData("{\"status\": \"wait\"}", StatusCode.OK);
            }
            default: {
                return new ResponseData("{}", StatusCode.UNAUTHORIZED);
            }
        }
    }

    @RestRequest(path = "/refresh", method = "POST")
    public static ResponseData token(RequestData data) {
        String token = data.getHeader("token");
        if (token == null)
            return new ResponseData("{}", StatusCode.UNAUTHORIZED);
        try {
            DecodedJWT jwt = AuthService.REFRESH_VERIFIER.verify(token);
            String keyId = jwt.getKeyId();
            Token tok = Token.get(keyId);
            JSONObject result = new JSONObject();
            result.put("token", tok.generateToken());
            result.put("refreshToken", tok.generateRefreshToken());
            result.put("id", tok.getUserId());
            return new ResponseData(result.toString(), StatusCode.OK);
        } catch (Exception e) {
            return new ResponseData("{}", StatusCode.UNAUTHORIZED);
        }
    }

    private static ResponseData getTokens(AuthStatus status, String username) {
        UserDetailsImpl authentication = UserDetailsImpl.build((AccountData) AuthService.DATABASE.getTable(AccountData.class).query().addParameter("username", username).executeOne());
        AuthenticationManager.setAuthentication(authentication);

        TokenResponse tokenResponse = AuthService.JWT_UTILS.generateJwtToken(authentication, status);
        if (tokenResponse == null) return new ResponseData("{}", StatusCode.INTERNAL_SERVER_ERROR);
        tokenResponse.setId(authentication.getId());
        return new ResponseData(new Gson().toJson(tokenResponse), StatusCode.OK);
    }

    @RestRequest(path = "/password", method = "POST")
    public static ResponseData getPassword(@RequestBody String password) {
        return new ResponseData(new JSONObject().put("password", BCrypt.hashpw(password, BCrypt.gensalt())).toString(), StatusCode.OK);
    }

}
