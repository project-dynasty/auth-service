package com.projectdynasty.example;

import de.alexanderwodarz.code.database.AbstractTable;
import de.alexanderwodarz.code.database.Database;
import de.alexanderwodarz.code.database.annotation.Column;
import de.alexanderwodarz.code.database.annotation.Table;
import lombok.Getter;

@Table(name = "account_data")
@Getter
public class TableAccount extends AbstractTable {

    @Column(name = "user_id")
    public long userId;

    @Column(name = "username")
    public String username;

    @Column(name = "last_name")
    public String lastName;

    @Column(name = "first_name")
    public String firstName;

    public TableAccount(Database database) {
        super(database);
    }
}
