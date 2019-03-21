@echo off

REM set signing certificate thumbprint
set KEY=dee492a6b2cbfd39631c68eb04b65057e049cfc2
set TSA=http://timestamp.globalsign.com/scripts/timstamp.dll

REM set visual studio command line environment
call "C:\Program Files (x86)\Microsoft Visual Studio 12.0\Common7\Tools\VsDevCmd.bat"

REM sign DLLs
echo.
echo Signing the MSI
signtool sign /sha1 %KEY% /t %TSA% ".\bin\Release\PadesInfoProcessor.msi"

rem Copy output
echo.
echo Copying files

xcopy /YQ ".\bin\Release\PadesInfoProcessor.msi"			"build\*.*"

echo.
echo All done.
