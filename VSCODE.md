# VSCODE IDE support

## Introduction
Configuration details for navigation (IntelliSense) and debugin support for VSCode IDE.

## Freely navigate crates
The Trustification has many packages, with many internal dependencies in other parts of the Trust project.
VSCode needs to explicitly know about a package in the Trust project to give visibility for modules references to help resolution and IntelliSense features.

To do so, in VSCode settings.json file (either locally in `./.vscode/settings.json` file or in global VSCode settings) :
- Add the main `Cargo.toml` path 
- Add each package's Cargo.toml path (i.e spog/ui/Cargo.toml, etc) 
```
{
    "rust-analyzer.linkedProjects": [
        "Cargo.toml",
        "spog/ui/Cargo.toml"
        "vexination/vexination/Cargo.toml"
        "vexination/walker/Cargo.toml"

    ]
}
```
With the above setup in place you can start vscode from a project directory and have the full project perspective in place.

## Debug code within VSCode
The following extension must be installed in order to debug Rust code on VSCode :
- On Linux use [CodeLLDB](https://marketplace.visualstudio.com/items?itemName=vadimcn.vscode-lldb) extension 
- On Windows use [Microsoft C++](https://marketplace.visualstudio.com/items?itemName=vadimcn.vscode-lldb) extension.
  
The [Rust Analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer) extension provides the Rust Language Server and also pilots the debugger.

See https://code.visualstudio.com/docs/languages/rust for details.


You can add a debuging entry in the `./vscode/launch.json` file, for exemple: 

```
{
    "version": "0.2.0",
    "configurations": [
        {
            "type": "lldb",
            "request": "launch",
            "name": "Debug 'vexination' API",
            "cargo": {
                "args": [
                    "build",
                    "--bin=trust",
                    "-p",
                    "trust"
                ]
            },
            "args": [
                "vexination",
                "api",
                "--devmode"
            ],
            "cwd": "${workspaceFolder}"
        }
    ]
}
```

Another exemple, for runing the Vexination walker: 
```
        {
            "type": "lldb",
            "request": "launch",
            "name": "Debug 'vexination' walker",
            "cargo": {
                "args": [
                    "build",
                    "--bin=trust",
                    "-p",
                    "trust"
                ]   
            },
            "args": [
                "vexination",
                "walker",
                "--devmode",
                "--sink",
                "http://localhost:8081/api/v1/vex", 
                "--source",
                "https://www.redhat.com/.well-known/csaf/provider-metadata.json",
                "-3"],
            "cwd": "${workspaceFolder}"
        }
```


