#include <iostream>
#include "sqlite/sqlite3.h"
#include <string>
#include "userauth.h"
#include "crypter.h"

using namespace std;
int signup();
string login();
bool auth(sqlite3* db, const char* username, const char* password);
void addcred(sqlite3* db, string name, int rc);
int show(sqlite3* db, string name, int rc);

string encrypt(string passwd, string passgen);
string decrypt(string passwd, string passdcrpt);

extern string dpassword;

int main() {

    int i;
    string cmd;
    string name;
    cout << "Enter 1 to login and 2 to signup" << endl;
    cin >> i;

    if (i == 1) {
        name = login();
    }
    else if (i == 2) {
        signup();
    }
    else {
        cout << "Enter between 1 and 2" << endl;
    }

    sqlite3* db;
    string Databasename = "Databases\\" + name + ".db";

    int rc = sqlite3_open(Databasename.c_str(), &db);
    if (rc != SQLITE_OK) {
        std::cout << "Error opening database: " << sqlite3_errmsg(db) << std::endl;
        return 1;
    }
    
    while (true) {
        cout << ">> ";
        cin >> cmd;
        if (cmd == "add") {
            addcred(db, name, rc);
        }
        else if (cmd == "show") {
            show(db, name, rc);
        }
        else if (cmd == "q") {
            sqlite3_close(db);
            exit(EXIT_SUCCESS);
        }
        else if (cmd == "help") {
            cout << "add : To add new credentials\nshow : To show all the credentials\nhelp : To show this help menu\n" << endl;
        }
        else {
            cout << dpassword << "\n";

        }
    }

    return 0;
}

int show(sqlite3* db, std::string name, int rc) {

    // Select all rows from the table.
    const char *sql = "SELECT * FROM creds;";
    sqlite3_stmt* stmt;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        std::cout << "Error preparing statement: " << sqlite3_errmsg(db) << std::endl;
        return 1;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {

        int id = sqlite3_column_int(stmt, 0);
        const char* service = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        const char* username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        const char* epassword = reinterpret_cast<const char*>(sqlite3_column_blob(stmt, 3));

        string decpassword = decrypt(dpassword,epassword);

        std::cout << "id: " << id << "\nService: " << service << "\nusername: " << username << "\npassword: " << decpassword << std::endl;
    }

    sqlite3_finalize(stmt);

    return 0;
}

void addcred(sqlite3* db, std::string name, int rc) {

    // Create a table.
    const char* sql = "CREATE TABLE IF NOT EXISTS creds (id INTEGER PRIMARY KEY, service TEXT, username TEXT, password BLOB);";
    rc = sqlite3_exec(db, sql, NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        cout << "Error creating table: " << sqlite3_errmsg(db) << endl;
    }

    cout << "Enter the Service: ";
    string service;
    cin >> service;

    cout << "Enter a username: ";
    string username;
    cin >> username;

    cout << "Enter a password: ";
    string password;
    cin >> password;

    string epassword = encrypt(dpassword, password);

    // Insert the row into the table.
    sql = "INSERT INTO creds (service, username, password) VALUES (?, ?, ?);";
    sqlite3_stmt* stmt;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        cout << "Error preparing statement: " << sqlite3_errmsg(db) << endl;
    }

    sqlite3_bind_text(stmt, 1, service.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 3, epassword.c_str(), epassword.size(), SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        cout << "Error inserting row: " << sqlite3_errmsg(db) << endl;
    }

    sqlite3_finalize(stmt);

}