package com.projectdynasty.models;

import de.alexanderwodarz.code.database.AbstractTable;
import de.alexanderwodarz.code.database.Database;
import de.alexanderwodarz.code.database.annotation.Column;
import de.alexanderwodarz.code.database.annotation.Table;

@Table(name = "account_data")
public class AccountData extends AbstractTable {

    @Column(name = "user_id")
    public long userId;

    @Column(name = "username")
    public String username;

    @Column(name = "last_name")
    public String lastName;

    @Column(name = "first_name")
    public String firstName;

    @Column(name = "disabled")
    public boolean disabled;

    public AccountData(Database database) {
        super(database);
    }
}
