package com.projectdynasty.security.jwt;

import com.projectdynasty.AuthService;
import com.projectdynasty.models.AccountData;
import com.projectdynasty.security.services.UserDetailsImpl;
import de.alexanderwodarz.code.web.rest.RequestData;
import de.alexanderwodarz.code.web.rest.authentication.AuthenticationFilter;
import de.alexanderwodarz.code.web.rest.authentication.AuthenticationFilterResponse;
import de.alexanderwodarz.code.web.rest.authentication.AuthenticationManager;
import de.alexanderwodarz.code.web.rest.authentication.CorsResponse;

import java.util.ArrayList;
import java.util.List;

public class AuthTokenFilter extends AuthenticationFilter {

    public static AuthenticationFilterResponse doFilter(RequestData request) {
        List<String> allowed = new ArrayList<>();
        allowed.add("/signin");
        allowed.add("/otp");
        allowed.add("/status");
        allowed.add("/otp");
        allowed.add("/challenge");
        allowed.add("/password");
        allowed.add("/refresh");
        if(allowed.contains(request.getPath()))
            return AuthenticationFilterResponse.OK();
        try {
            String jwt = parseJwt(request.getAuthorization());
            if (jwt != null && AuthService.JWT_UTILS.validateJwtToken(jwt)) {
                String username = AuthService.JWT_UTILS.getSubject(jwt);
                AccountData account = (AccountData) AuthService.DATABASE.getTable(AccountData.class).query().addParameter("username", username).executeOne();
                if (account == null) {
                    return AuthenticationFilterResponse.UNAUTHORIZED();
                }
                AuthenticationManager.setAuthentication(UserDetailsImpl.build(account));
                return AuthenticationFilterResponse.OK();
            }
        } catch (Exception e) {

        }
        return AuthenticationFilterResponse.UNAUTHORIZED();
    }

    public static CorsResponse doCors(RequestData data) {
        CorsResponse response = new CorsResponse();
        response.setCredentials(true);
        response.setOrigin("*");
        response.setHeaders("authorization, content-type, token");
        return response;
    }

    public static String parseJwt(String header) {
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        return null;
    }
}