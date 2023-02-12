package com.projectdynasty.controller;

import com.google.gson.Gson;
import com.projectdynasty.AuthService;
import com.projectdynasty.models.AccountData;
import com.projectdynasty.models.AuthenticationData;
import com.projectdynasty.models.RefreshTokenData;
import com.projectdynasty.payload.request.AuthStatus;
import com.projectdynasty.payload.request.SigninRequest;
import com.projectdynasty.payload.request.TwoFARequest;
import com.projectdynasty.security.jwt.Token;
import com.projectdynasty.security.services.UserDetailsImpl;
import de.alexanderwodarz.code.web.StatusCode;
import de.alexanderwodarz.code.web.rest.ResponseData;
import de.alexanderwodarz.code.web.rest.annotation.*;
import de.alexanderwodarz.code.web.rest.authentication.AuthenticationManager;
import org.json.JSONObject;
import org.mindrot.jbcrypt.BCrypt;

import java.security.KeyStore;
import java.util.*;

@RestController(path = "/auth", produces = "application/json")
public class AuthorizationController {

    private static final String password = "$2a$10$EEIui2SVbvqRU.SaA8amheB72OlbH6dxTvMABPZPcjURzXIg2R0pC";

    private static final Map<Long, SigninRequest> signinRequests = new HashMap<>();
    private static final Map<String, AuthStatus> permitted = new HashMap<>();

    private static final List<String> refreshToken = new ArrayList<>();

    // 5REULOJZNJN27PRR3XPIQ6CMUHJCB4RY

    @RestRequest(path = "/signin", method = "POST")
    public static ResponseData signin(@RequestBody String signin) {
        SigninRequest signinRequest = new Gson().fromJson(signin, SigninRequest.class);
        if (signinRequest == null || signinRequest.getUsername() == null)
            return new ResponseData("{}", StatusCode.BAD_REQUEST);
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
        status.setMobile(signinRequest.getOsType() != null || signinRequest.getOsVersion() != null);

        signinRequests.put(accountData.userId, signinRequest);
        if (authenticationData.getAuthOtpMobileValue() != null && !authenticationData.getAuthOtpMobileValue().equals("")) {

            String token = AuthService.JWT_UTILS.generateAuthToken(accountData.userId);

            /*if (signinRequest.getOsType() != null || signinRequest.getOsVersion() != null) {
                DeviceData deviceData = new DeviceData();
                osVersion.ifPresent(deviceData::setOsVersion);
                osType.ifPresent(deviceData::setOsType);
                deviceData.setAccount(accountRepository.findById(userDetails.getId()).orElse(null));
                deviceData.setIpv4Address(getIPFromRequest(request));
                DeviceData device = deviceRepository.save(deviceData);
                deviceId = device.getId();
            }*/

            status.setOtp(true);
            status.setStatus("wait");
            status.setToken(token);
            status.setMobileConfirm(new Random().nextInt(1000));
            status.setFakeOne(new Random().nextInt(1000));
            status.setFakeTwo(new Random().nextInt(1000));
            //status.setDeviceId(deviceId);
            status.setId(accountData.userId);
            /*List<DeviceData> devices = deviceRepository.findByAccount(accountRepository.findById(userDetails.getId()).get());
            boolean sentCode = false;
            if (devices.size() > 0) {
                for (DeviceData deviceData : devices) {
                    if (deviceData.getDeviceToken() != null && deviceData.getDeviceToken().length() > 0) {
                        sentCode = true;
                        PushNotification.trigger2fa(deviceData.getDeviceToken(), token, status.getFakeOne() + "," + status.getMobileConfirm() + "," + status.getFakeTwo());
                    }
                }
            }*/
            boolean sentCode = false;
            permitted.put(token, status);
            return new ResponseData("{\"token\": \"" + token + "\", \"mobile\": \"" + (sentCode ? status.getMobileConfirm() : 0) + "\", \"username\": \"" + accountData.username + "\"}", StatusCode.OK);
        }
        return getTokens(status, signinRequest.getUsername());
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

    @RestRequest(path = "/mobile", method = "POST")
    public static ResponseData mobile(@RequestBody String mobile) {
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
    public static ResponseData token(@RequestBody String body) {
        JSONObject object = new JSONObject(body);
        if (!object.has("token")) return new ResponseData("{}", StatusCode.UNAUTHORIZED);
        String token = object.getString("token");
        RefreshTokenData tokenData = (RefreshTokenData) AuthService.DATABASE.getTable(RefreshTokenData.class).query().addParameter("token", token).executeOne();
        if (tokenData == null) return new ResponseData("{}", StatusCode.NOT_FOUND);
        if (!AuthService.JWT_UTILS.validateJwtRefreshToken(token)) {
            tokenData.delete();
            return new ResponseData("{}", StatusCode.NOT_FOUND);
        }
        tokenData.delete();

        Token newTokens = AuthService.JWT_UTILS.fromRefreshToken(token);
        insert(newTokens.getRefreshToken());

        return new ResponseData(new Gson().toJson(newTokens), StatusCode.OK);
    }

    private static ResponseData getTokens(AuthStatus status, String username) {
        UserDetailsImpl authentication = UserDetailsImpl.build((AccountData) AuthService.DATABASE.getTable(AccountData.class).query().addParameter("username", username).executeOne());
        AuthenticationManager.setAuthentication(authentication);

        Token token = AuthService.JWT_UTILS.generateJwtToken(authentication, status);
        if (token == null) return new ResponseData("{}", StatusCode.INTERNAL_SERVER_ERROR);
        insert(token.getRefreshToken());
        token.setId(authentication.getId());
        return new ResponseData(new Gson().toJson(token), StatusCode.OK);
    }

    private static void insert(String token) {
        RefreshTokenData refreshTokenData = AuthService.DATABASE.getTable(RefreshTokenData.class);
        refreshTokenData.token = token;
        refreshTokenData.insert();
    }

    @RestRequest(path = "/password", method = "POST")
    public static ResponseData getPassword(@RequestBody String password) {
        return new ResponseData(new JSONObject().put("password", BCrypt.hashpw(password, BCrypt.gensalt())).toString(), StatusCode.OK);
    }

}
