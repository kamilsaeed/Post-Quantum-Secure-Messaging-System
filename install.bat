@echo off
echo Installing Backend Dependencies...
cd pq_backend
call npm install
cd ..

echo.
echo Installing Frontend Dependencies...
cd pq_frontend
call npm install
cd ..

echo.
echo Installation Complete! You can now run the app using start.bat
pause
