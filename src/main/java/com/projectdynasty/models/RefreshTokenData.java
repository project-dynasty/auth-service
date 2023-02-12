package com.projectdynasty.models;

import de.alexanderwodarz.code.database.AbstractTable;
import de.alexanderwodarz.code.database.Database;
import de.alexanderwodarz.code.database.annotation.Column;
import de.alexanderwodarz.code.database.annotation.Table;
import lombok.Getter;

@Table(name = "refresh_tokens")
@Getter
public class RefreshTokenData extends AbstractTable {

    @Column(name = "id", primaryKey = true, autoIncrement = true)
    public long id;

    @Column(name = "token")
    public String token;

    public RefreshTokenData(Database database) {
        super(database);
    }
}
