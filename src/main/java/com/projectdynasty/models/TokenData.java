package com.projectdynasty.models;

import de.alexanderwodarz.code.database.AbstractTable;
import de.alexanderwodarz.code.database.Database;
import de.alexanderwodarz.code.database.annotation.Column;
import de.alexanderwodarz.code.database.annotation.Table;
import de.alexanderwodarz.code.database.enums.ColumnDefault;

@Table(name = "token_data")
public class TokenData extends AbstractTable {

    @Column(length = 32, primaryKey = true, defaultValue = ColumnDefault.RANDOM_STRING)
    public String id;

    @Column(name = "user_id")
    public long userId;

    @Column
    public long created;

    @Column
    public boolean mobile;

    @Column
    public boolean challenge;

    @Column
    public boolean otp;

    @Column
    public long deviceId;

    @Column
    public long last;

    @Column
    public long expires;

    public TokenData(Database database) {
        super(database);
    }
}
