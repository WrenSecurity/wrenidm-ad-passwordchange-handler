# Wren:IDM Active Directory Password Change Handler

This component enables synchronization of passwords from the Active Directory domain controller to the Wren:IDM.

## Getting the application

You can get Wren:IDM AD Password Change Handler in couple of ways:

### Download binary release

Downloading the latest binary [release](https://github.com/WrenSecurity/wrenidm-ad-passwordchange-handler/releases) is the easiest way.

### Build the source code

In order to build the project from the command line follow these steps:

**Prepare your Environment**

Following software is needed to build the project:

* OpenJDK 17+
* Apache Ant 1.10.14
* Inno Setup 6.2.2
* Build Tools for Visual Studio 2022

**Build the source code**

To build the project, simply run Apache Ant *build* task.

```
$ cd $GIT_REPOSITORIES/wrenidm-ad-passwordchange-handler
$ ant build
```

Built binary can be found in `${GIT_REPOSITORIES}/wrenidm-ad-passwordchange-handler/out/idmsync-setup.exe`.