@echo off
cd /d "%~dp0"
title JMCL Web Server - http://localhost:3000
echo =======================================================
echo JMCL Web Server
echo URL: http://localhost:3000
echo Admin: http://localhost:3000/admin
echo =======================================================
echo.
node server.js
pause

