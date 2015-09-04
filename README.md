# jenkins-plugin
This plugin allows you to run web security tests from the cloud using Tinfoil Security.

## Development

Install the latest and greatest JDK from Oracle.

http://www.oracle.com/technetwork/java/javase/downloads/index.html

Install `maven`.  I used `brew` to install it.

```$ brew install maven```

Make sure the project builds without Eclipse first. From the root of this repo, run the following.

```mvn package```

Download Eclipse for Java. I used `brew-cask` for this.

```$ brew cask install eclipse-java```

Open Eclipse and make a workspace. Then run the following command (which is really two commands in one) from the repo root to a) sync the maven dependencies with the eclipse classpath and b) make this project compatible with your Eclipse.

```mvn -DdownloadSources=true -DdownloadJavadocs=true -DoutputDirectory=target/eclipse-classes -Declipse.workspace=/path/to/your/workspace eclipse:eclipse eclipse:add-maven-repo```

Import this project into Eclipse using File > Import... > General > Existing Projects Into Workspace

Make sure you have your M2_REPO classpath variable set properly. Mine wasn't set at all.

* Open the Eclipse Preferences menu
* Go to [Java - Build Path - Classpath Variables]
* Click 'New' and set its name as M2_REPO
* Click 'Folder' and select your Maven repository folder `(~/.m2/repository)`.

Eclipse will prompt you to rebuild the project. Make sure that this returns no build errors. Warnings are OK.

## Testing

```mvn hpi:run```

This will run Jenkins with your Tinfoil plugin as an available plugin. Now you can install the plugin and use it. Jenkins by default runs on port 8080. If you need a different port, use the `jetty.port` option.

```mvn hpi:run -Djetty.port=8090```

## Adding a library

Dependency management is handled by Maven. The file that stores dependencies is `pom.xml`. Never write to this file directly. Use Eclipse's editor instead.

After adding a dependency to the `pom.xml`, you need to do two things to get Eclipse to understand that it exists.

1. In the project root directory, run `mvn eclipse:eclipse`
2. In Eclipse, hit F5 to refresh.