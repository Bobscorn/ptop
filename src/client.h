#pragma once

#include <stdio.h>
#include "socket.h"

std::unique_ptr<ISenderSocket> create_client();