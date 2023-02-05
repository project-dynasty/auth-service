package com.projectdynasty.models;

import de.alexanderwodarz.code.database.AbstractTable;
import de.alexanderwodarz.code.database.Database;
import de.alexanderwodarz.code.database.annotation.Column;
import de.alexanderwodarz.code.database.annotation.Table;
import lombok.Getter;


@Table(name = "authentication_data")
@Getter
public class AuthenticationData extends AbstractTable {

    @Column(name = "user_id")
    public long userId;

    @Column(name = "password")
    public String password;

    @Column(name = "auth_otp_mobile_value")
    public String authOtpMobileValue;

    @Column(name = "register_token")
    public String registerToken;

    public AuthenticationData(Database database) {
        super(database);
    }
}
