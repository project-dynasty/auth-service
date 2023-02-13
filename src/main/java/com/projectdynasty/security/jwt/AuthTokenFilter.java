package com.projectdynasty.security.jwt;

import com.projectdynasty.AuthService;
import com.projectdynasty.models.AccountData;
import de.alexanderwodarz.code.web.rest.RequestData;
import de.alexanderwodarz.code.web.rest.authentication.AuthenticationFilter;
import de.alexanderwodarz.code.web.rest.authentication.AuthenticationFilterResponse;
import de.alexanderwodarz.code.web.rest.authentication.CorsResponse;

public class AuthTokenFilter extends AuthenticationFilter {

    public static AuthenticationFilterResponse doFilter(RequestData request) {
        if (request.getPath().startsWith("/auth") || request.getPath().startsWith("/twofa")) return AuthenticationFilterResponse.OK();
        try {
            String jwt = parseJwt(request.getAuthorization());
            if (jwt != null && AuthService.JWT_UTILS.validateJwtToken(jwt)) {
                String username = AuthService.JWT_UTILS.getSubject(jwt);
                AccountData account = (AccountData) AuthService.DATABASE.getTable(AccountData.class).query().addParameter("username", username).executeOne();
                if (account == null) {
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
        response.setCredentials(true);
        if(data.getHeader("origin").contains("capacitor"))
            response.setOrigin("capacitor://localhost");
        else
            response.setOrigin("https://tcp.project-dynasty.com");
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