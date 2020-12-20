# Dexter

## Compile

`gradlew build`


## From jar to .dex

We want a dex file to make it run on android.

Use `dx` for that. On Windows, it is located at `%USERPROFILE%AppData\Local\Android\Sdk\build-tools\<version>`
where `<version>` is your build tools version.

```bash
dx --dex --output="/path/to/classes.dex" "/path/to/file.jar"
```

## Executing the dex file on an Android device.

Zip it first:

```
zip HelloWorld.zip classes.dex
```

Put it on your phone (example):

```
adb push Helloworld.zip /sdcard/
```

Run it through dalvikvm.

```
adb shell dalvikvm -cp /sdcard/HelloWorld.zip dev.ge0.dexter.MainKt
```