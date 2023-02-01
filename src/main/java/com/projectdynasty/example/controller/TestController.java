package com.projectdynasty.example.controller;

import com.projectdynasty.example.Auth;
import com.projectdynasty.example.Main;
import com.projectdynasty.example.TableAccount;
import de.alexanderwodarz.code.web.StatusCode;
import de.alexanderwodarz.code.web.rest.ResponseData;
import de.alexanderwodarz.code.web.rest.annotation.PathVariable;
import de.alexanderwodarz.code.web.rest.annotation.RequestBody;
import de.alexanderwodarz.code.web.rest.annotation.RestController;
import de.alexanderwodarz.code.web.rest.annotation.RestRequest;
import de.alexanderwodarz.code.web.rest.authentication.AuthenticationManager;
import org.json.JSONObject;

@RestController(path = "/test", produces = "application/json")
public class TestController {

    @RestRequest(path = "/{userId}", method = "GET")
    public static ResponseData test(@RequestBody String body, @PathVariable("userId") String userId) {
        Auth auth = (Auth) AuthenticationManager.getAuthentication();
        TableAccount account = (TableAccount) Main.database.getTable(TableAccount.class).query().addParameter("user_id", userId).executeOne();
        if(account == null)
            return new ResponseData("{}", StatusCode.NOT_FOUND);
        JSONObject obj = new JSONObject();
        obj.put("userId", userId);
        obj.put("username", account.username);
        obj.put("firstName", account.firstName);
        obj.put("lastName", account.lastName);
        return new ResponseData(obj.toString(), StatusCode.OK);
    }

}
