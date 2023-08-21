#pragma once

#ifndef USER_H
#define USER_H

std::string md5gen(string passwd);
std::string encrypt(string passwd, string passgen);
std::string decrypt(string passwd, string passdcrpt);

#endif