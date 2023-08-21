#include <iostream>
#include "sqlite/sqlite3.h"
#include "userauth.h"
#include "crypter.h"

using namespace std;
string md5gen(string passwd);
std::string dpassword;

int signup() {

    // Open the database file.
    sqlite3* db;
    int rc = sqlite3_open("plasmausers.db", &db);
    if (rc != SQLITE_OK) {
        cout << "Error opening database: " << sqlite3_errmsg(db) << endl;
        return 1;
    }

    // Create a table.
    const char* sql = "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, password TEXT);";
    rc = sqlite3_exec(db, sql, NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        cout << "Error creating table: " << sqlite3_errmsg(db) << endl;
        return 1;
    }

    // Get user input.
    cout << "Enter the name: ";
    string name;
    cin >> name;

    cout << "Enter a strong password: ";
    string password;
    cin >> password;

    cout << "Enter the password again: ";
    string password2;
    cin >> password2;

    if (password != password2) {
        cout << "Password didn't match!!";
    }

    string password3 = md5gen(password);

    // Insert the row into the table.
    sql = "INSERT INTO users (name, password) VALUES (?, ?);";
    sqlite3_stmt* stmt;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        cout << "Error preparing statement: " << sqlite3_errmsg(db) << endl;
        return 1;
    }

    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, password3.c_str(), -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        cout << "Error inserting row: " << sqlite3_errmsg(db) << endl;
        return 1;
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);

    exit(EXIT_SUCCESS);
}

string login() {
    // Open the database file.
    sqlite3* db;
    int rc = sqlite3_open("plasmausers.db", &db);
    if (rc != SQLITE_OK) {
        cout << "Error opening database: " << sqlite3_errmsg(db) << endl;
    }

    // Get the username and password from the user.
    cout << "Enter your username: ";
    string username;
    cin >> username;

    cout << "Enter your password: ";
    cin >> dpassword;

    // Check if the user is authenticated.
    bool is_authenticated = auth(db, username.c_str(), dpassword.c_str());
    if (is_authenticated) {
        cout << "Login successful." << endl;
        return username;
    }
    else {
        cout << "Login failed." << endl;
    }

    sqlite3_close(db);
}


bool auth(sqlite3* db, const char* username, const char* password) {

    // Check if the user exists.
    const char* sql = "SELECT * FROM users WHERE name = ?;";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        std::cout << "Error preparing statement: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);

    // Execute the statement.
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        // The user does not exist.
        sqlite3_finalize(stmt);
        return false;
    }

    // Get the password from the row.
    const char* db_password = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
    string password2 = md5gen(password);

    // Compare the passwords.
    if (strcmp(password2.c_str(), db_password) == 0) {
        sqlite3_finalize(stmt);
        return true;
    }
    else {
        sqlite3_finalize(stmt);
        return false;
    }
}