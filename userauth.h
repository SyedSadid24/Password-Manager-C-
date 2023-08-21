#pragma once

#ifndef USER_H
#define USER_H

int signup();
std::string login();
bool auth(sqlite3* db, const char* username, const char* password);

#endif