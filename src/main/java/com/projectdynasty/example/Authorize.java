package com.projectdynasty.example;

import de.alexanderwodarz.code.web.rest.RequestData;
import de.alexanderwodarz.code.web.rest.authentication.AuthenticationFilter;
import de.alexanderwodarz.code.web.rest.authentication.AuthenticationFilterResponse;
import de.alexanderwodarz.code.web.rest.authentication.AuthenticationManager;
import de.alexanderwodarz.code.web.rest.authentication.CorsResponse;

public class Authorize extends AuthenticationFilter {

    public static AuthenticationFilterResponse doFilter(RequestData request) {
        if(request.getPath().startsWith("/test")) {
            Auth auth = new Auth(request.getHeader("Authorization"));
            AuthenticationManager.setAuthentication(auth);
            return AuthenticationFilterResponse.OK();
        }
        AuthenticationFilterResponse response = new AuthenticationFilterResponse();
        response.setError("{\"error\": \"KEINE AUTORISIERUNG\"}");
        response.setCode(418);
        response.setAccess(false);
        return response;
    }

    public static CorsResponse doCors(RequestData data) {
        CorsResponse response = new CorsResponse();
        response.setOrigin(data.getHeader("origin"));
        response.setHeaders("authorization, content-type");
        return response;
    }

}
