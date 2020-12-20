@echo off
call gradlew build
call dx --dex --output=classes.dex build\libs\dexter-0.0.1-SNAPSHOT.jar
call rm HelloWorld.zip
call "C:\\Program Files\\WinRAR\\WinRAR.exe" a HelloWorld.zip classes.dex
call adb push Helloworld.zip /sdcard/
call adb shell dalvikvm -cp /sdcard/HelloWorld.zip dev.ge0.dexter.MainKt