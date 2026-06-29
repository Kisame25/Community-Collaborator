@echo off
setlocal enabledelayedexpansion

set "LIB_DIR=lib"
set "SRC_DIR=src"
set "OUT_DIR=build\classes"
set "JAR_NAME=community-collaborator.jar"

if exist "%OUT_DIR%" rd /s /q "%OUT_DIR%"
mkdir "%OUT_DIR%"

echo [INFO] Finding source files...
dir /s /b "%SRC_DIR%\*.java" > sources.txt

echo [INFO] Compiling source files...
javac -d "%OUT_DIR%" -cp "%LIB_DIR%\montoya-api.jar" @sources.txt

if %ERRORLEVEL% neq 0 (
    echo [ERROR] Compilation failed.
    del sources.txt
    exit /b %ERRORLEVEL%
)

echo [INFO] Creating fat JAR...
if exist "build\fat" rd /s /q "build\fat"
mkdir "build\fat"

xcopy /s /e /y "%OUT_DIR%\*" "build\fat\" > nul

echo [INFO] Extracting dependencies...
cd "build\fat"
jar xf "..\..\lib\montoya-api.jar"
cd ..\..

jar cvf "%JAR_NAME%" -C "build\fat" .

if %ERRORLEVEL% neq 0 (
    echo [ERROR] JAR creation failed.
    del sources.txt
    exit /b %ERRORLEVEL%
)

del sources.txt
echo [INFO] Build successful: %JAR_NAME%
endlocal
