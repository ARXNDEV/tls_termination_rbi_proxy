#pragma once
#include <string>
#include <iostream>
#include <sstream>
#include <vector>
#include <algorithm>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <string>
#include <sstream>
#include <iostream>
#include <QDir>
using namespace std;

class HttpRequest
{
    public:
        string getUri();
        string getVersion();
        string getMethod();
        string getHost();
        string getRequest();

        void parse(string req);
        HttpRequest(string req); //parse request
    private:
        string method;
        string uri;
        string version;
        string host;
        string req;
    };

