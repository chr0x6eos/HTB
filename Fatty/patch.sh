#!/bin/bash
/usr/lib/jvm/java-8-openjdk-amd64/bin/javac htb/fatty/client/methods/Invoker.java 2>/dev/null
/usr/lib/jvm/java-8-openjdk-amd64/bin/javac htb/fatty/client/gui/ClientGuiTest.java 2>/dev/null
jar uf fatty-client.jar htb/fatty/client/gui/* 2>/dev/null
jar uf fatty-client.jar htb/fatty/client/methods/* 2>/dev/null
echo "secureclarabibi123" | jarsigner -storetype pkcs12 -keystore fatty.p12 fatty-client.jar 1
/usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java -jar fatty-client.jar
