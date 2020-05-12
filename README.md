# GSatMicroPublicJava
Java examples for interfacing to the GSatMicro

#Build a Ping message to a specific device, with a valid HMAC
CLASSPATH=commons-codec.jar:commons-lang.jar:.; javac -Xdiags:verbose -Xlint:unchecked -cp $CLASSPATH GSatMicroMessageToMobile.java && java -cp $CLASSPATH GSatMicroMessageToMobile
