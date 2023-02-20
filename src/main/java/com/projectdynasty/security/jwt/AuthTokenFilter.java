package com.projectdynasty.security.jwt;

import com.projectdynasty.AuthService;
import com.projectdynasty.models.AccountData;
import com.projectdynasty.security.services.UserDetailsImpl;
import de.alexanderwodarz.code.web.rest.RequestData;
import de.alexanderwodarz.code.web.rest.authentication.AuthenticationFilter;
import de.alexanderwodarz.code.web.rest.authentication.AuthenticationFilterResponse;
import de.alexanderwodarz.code.web.rest.authentication.AuthenticationManager;
import de.alexanderwodarz.code.web.rest.authentication.CorsResponse;

public class AuthTokenFilter extends AuthenticationFilter {

    public static AuthenticationFilterResponse doFilter(RequestData request) {
        if ((request.getPath().startsWith("/auth") && !request.getPath().equals("/auth/challenge/solve") && !request.getPath().equals("/auth/challenge/claim") && !request.getPath().equals("/auth/challenge/unclaim")) || request.getPath().startsWith("/twofa"))
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

    private static String parseJwt(String header) {
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        return null;
    }
}