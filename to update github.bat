@echo off
set /p msg=Enter commit message: 
echo 🚀 Adding all changes...
git add .
echo 🧾 Committing...
git commit -m "%msg%"
echo 📤 Pushing...
git push
echo ✅ Done!
pause
