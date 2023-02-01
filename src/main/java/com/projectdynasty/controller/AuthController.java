package com.projectdynasty.controller;

import com.google.gson.Gson;
import com.projectdynasty.AuthService;
import com.projectdynasty.models.AccountData;
import com.projectdynasty.payload.request.AuthStatus;
import com.projectdynasty.payload.request.SigninRequest;
import com.projectdynasty.security.services.UserDetailsImpl;
import de.alexanderwodarz.code.web.StatusCode;
import de.alexanderwodarz.code.web.rest.ResponseData;
import de.alexanderwodarz.code.web.rest.annotation.RequestBody;
import de.alexanderwodarz.code.web.rest.annotation.RestController;
import de.alexanderwodarz.code.web.rest.annotation.RestRequest;
import org.mindrot.jbcrypt.BCrypt;

import java.security.KeyStore;

@RestController(path = "/auth")
public class AuthController {

    private static final String password = "$2a$10$EEIui2SVbvqRU.SaA8amheB72OlbH6dxTvMABPZPcjURzXIg2R0pC";

    @RestRequest(path = "/signin", method = "POST")
    public static ResponseData signin(@RequestBody String signin) {
        SigninRequest signinRequest = new Gson().fromJson(signin, SigninRequest.class);
        System.out.println(signinRequest.getPassword());
        if (!BCrypt.checkpw(signinRequest.getPassword(), password))
            return new ResponseData("{}", StatusCode.UNAUTHORIZED);

        UserDetailsImpl authentication = UserDetailsImpl.build((AccountData) AuthService.DATABASE.getTable(AccountData.class).query().addParameter("username", signinRequest.getUsername()).executeOne());

        String token = AuthService.JWT_UTILS.generateJwtToken(authentication, new AuthStatus());
        return new ResponseData("{\"token\": \"" + token + "\"}", StatusCode.OK);
    }

}
