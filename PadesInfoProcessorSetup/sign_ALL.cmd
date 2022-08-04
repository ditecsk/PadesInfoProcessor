@echo off

REM set signing certificate thumbprint
set KEY=9633a3f6a4d6e6f8c7298e2cc4f856cd787e5269
set TSA=http://rfc3161timestamp.globalsign.com/advanced

REM set visual studio command line environment
call "C:\Program Files (x86)\Microsoft Visual Studio 12.0\Common7\Tools\VsDevCmd.bat"

REM sign DLLs
echo.
echo Signing the MSI
signtool sign /fd SHA256 /sha1 %KEY% /tr %TSA% /td SHA256 ".\bin\Release\PadesInfoProcessor.msi"

rem Copy output
echo.
echo Copying files

xcopy /YQ ".\bin\Release\PadesInfoProcessor.msi"			"build\*.*"

echo.
echo All done.
