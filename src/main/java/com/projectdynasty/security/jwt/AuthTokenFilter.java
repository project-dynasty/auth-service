package com.projectdynasty.security.jwt;

import com.projectdynasty.AuthService;
import com.projectdynasty.example.TableAccount;
import de.alexanderwodarz.code.web.rest.RequestData;
import de.alexanderwodarz.code.web.rest.authentication.AuthenticationFilter;
import de.alexanderwodarz.code.web.rest.authentication.AuthenticationFilterResponse;
import de.alexanderwodarz.code.web.rest.authentication.CorsResponse;

public class AuthTokenFilter extends AuthenticationFilter {

    public static AuthenticationFilterResponse doFilter(RequestData request) {
        if(request.getPath().startsWith("/auth")) return AuthenticationFilterResponse.OK();
        try {
            String jwt = parseJwt(request.getAuthorization());
            if(jwt != null && AuthService.JWT_UTILS.validateJwtToken(jwt)) {
                String username = AuthService.JWT_UTILS.getSubject(jwt);
                TableAccount account = (TableAccount) AuthService.DATABASE.getTable(TableAccount.class).query().addParameter("username", username).executeOne();
                if(account == null) {
                    return AuthenticationFilterResponse.UNAUTHORIZED();
                }
                return AuthenticationFilterResponse.OK();
            }
        } catch (Exception e) {

        }
        return AuthenticationFilterResponse.UNAUTHORIZED();
    }

    public static CorsResponse doCors(RequestData data) {
        CorsResponse response = new CorsResponse();
        response.setOrigin(data.getHeader("origin"));
        response.setHeaders("authorization, content-type");
        return response;
    }

    private static String parseJwt(String header) {
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        return null;
    }
}