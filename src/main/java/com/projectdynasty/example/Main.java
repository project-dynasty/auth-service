package com.projectdynasty.example;

import de.alexanderwodarz.code.database.Database;
import de.alexanderwodarz.code.model.varible.VaribleMap;
import de.alexanderwodarz.code.web.WebCore;
import de.alexanderwodarz.code.web.rest.annotation.RestApplication;

import java.util.List;

@RestApplication
public class Main {

    public static Database database;
    public static void main(String[] args) throws Exception {
        database = new Database("185.244.166.140", "clusteradmin", "4BCk36hXCmpbmcEJEe79kARyEDbgtMkS", "users", true);
        List<TableAccount> accountList = database.getTable(TableAccount.class).query().executeMany();
        for (TableAccount tableAccount : accountList) {
            System.out.println(tableAccount.firstName);
        }
        VaribleMap map = new VaribleMap();
        map.put().setKey("port").setValue(6472).build();
        WebCore.start(Main.class, map);
    }
}