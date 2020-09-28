#!/bin/bash

curl -v  http://localhost:7071/admin/functions/ci-clean -d@trigger.json -H"Content-Type: application/json"
