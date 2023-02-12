package com.projectdynasty.controller;

import com.google.zxing.WriterException;
import com.projectdynasty.AuthService;
import com.projectdynasty.models.AccountData;
import com.projectdynasty.models.AuthenticationData;
import de.alexanderwodarz.code.database.AbstractTable;
import de.alexanderwodarz.code.database.update.UpdateSelector;
import de.alexanderwodarz.code.web.StatusCode;
import de.alexanderwodarz.code.web.rest.ResponseData;
import de.alexanderwodarz.code.web.rest.annotation.RequestBody;
import de.alexanderwodarz.code.web.rest.annotation.RestController;
import de.alexanderwodarz.code.web.rest.annotation.RestRequest;
import org.json.JSONObject;

import java.io.IOException;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@RestController(path = "/twofa", produces = "application/json")
public class TwoFactorController {

    public static final Map<Long, String> CREATE_MAP = new HashMap<>();

    @RestRequest(path = "/qr", method = "POST")
    public static ResponseData createQr(@RequestBody String body) throws IOException, WriterException, SQLException {
        JSONObject object = new JSONObject(body);
        String jwt = null;
        if (!object.has("token")) {
            if (!object.has("jwt")) return new ResponseData("{}", StatusCode.BAD_REQUEST);
            jwt = object.getString("jwt");
            if (!AuthService.JWT_UTILS.validateJwtToken(jwt)) return new ResponseData("{}", StatusCode.UNAUTHORIZED);
        }

        AuthenticationData authenticationData = object.has("token")
                ? (AuthenticationData) AuthService.DATABASE.getTable(AuthenticationData.class).query().addParameter("register_token", object.getString("token")).executeOne()
                : (AuthenticationData) AuthService.DATABASE.getTable(AuthenticationData.class).query().addParameter("user_id", object.getLong("id")).executeOne();

        if (authenticationData == null) return new ResponseData("{}", StatusCode.BAD_REQUEST);
        AccountData accountData = (AccountData) AuthService.DATABASE.getTable(AccountData.class).query().addParameter("user_id", authenticationData.user_id).executeOne();
        if (accountData == null || (jwt != null && !Objects.equals(accountData.username, AuthService.JWT_UTILS.getSubject(jwt))))
            return new ResponseData("{}", StatusCode.BAD_REQUEST);

        String username = accountData.username;
        String secret = AuthService.TWO_FACTOR.generateSecretKey();
        String company = "DYNASTY";

        String barcode = AuthService.TWO_FACTOR.getGoogleAuthenticatorBarCode(secret, username, company);
        String qr = AuthService.TWO_FACTOR.createQRCode(barcode, 400, 400);

        CREATE_MAP.put(authenticationData.user_id, secret);

        return new ResponseData(new JSONObject().put("secret", secret).put("qr", qr).toString(), StatusCode.OK);
    }

    @RestRequest(path = "/check", method = "POST")
    public static ResponseData checkCode(@RequestBody String body) {
        JSONObject object = new JSONObject(body);
        if (!object.has("code")) return new ResponseData("{}", StatusCode.BAD_REQUEST);

        String code = object.getString("code");
        if (!object.has("secret"))
            return new ResponseData("{}", StatusCode.BAD_REQUEST);

        if (code.equals(AuthService.TWO_FACTOR.getTOTPCode(object.getString("secret"))))
            return new ResponseData("{}", StatusCode.OK);
        return new ResponseData("{}", StatusCode.BAD_REQUEST);

        /*if (!object.has("userId")) return new ResponseData("{}", StatusCode.BAD_REQUEST);
        AuthenticationData authenticationData = (AuthenticationData) AuthService.DATABASE.getTable(AuthenticationData.class).query().addParameter("user_id", object.getLong("userId")).executeOne();

        if (authenticationData == null) return new ResponseData("{}", StatusCode.BAD_REQUEST);
        if (code.equals(AuthService.TWO_FACTOR.getTOTPCode(authenticationData.getAuthOtpMobileValue())))
            return new ResponseData("{}", StatusCode.OK);
        return new ResponseData("{}", StatusCode.BAD_REQUEST);*/
    }

}
