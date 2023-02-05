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
import java.util.Objects;

@RestController(path = "/twofa", produces = "application/json")
public class TwoFactorController {

    @RestRequest(path = "/qr", method = "GET")
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
        AccountData accountData = (AccountData) AuthService.DATABASE.getTable(AccountData.class).query().addParameter("user_id", authenticationData.getUserId()).executeOne();
        if (accountData == null || (jwt != null && !Objects.equals(accountData.username, AuthService.JWT_UTILS.getSubject(jwt))))
            return new ResponseData("{}", StatusCode.BAD_REQUEST);

        String username = accountData.username;
        String secret = AuthService.TWO_FACTOR.generateSecretKey();
        String company = "DYNASTY";

        String barcode = AuthService.TWO_FACTOR.getGoogleAuthenticatorBarCode(secret, username, company);
        String qr = AuthService.TWO_FACTOR.createQRCode(barcode, 400, 400);

        return new ResponseData(new JSONObject().put("secret", secret).put("qr", qr).toString(), StatusCode.OK);
    }

}
