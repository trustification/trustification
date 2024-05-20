# VSCODE IDE support

## Introduction

Configuration details for navigation (IntelliSense) and debugging support for VSCode IDE.

## Freely navigate crates

The Trustification has many packages, with many internal dependencies in other parts of the Trust project.
VSCode needs to explicitly know about a package in the Trust project to give visibility for modules references to help resolution and IntelliSense features.

To do so, in VSCode settings.json file (either locally in `./.vscode/settings.json` file or in global VSCode settings) :

- Add the main `Cargo.toml` path
- Add each package's Cargo.toml path (i.e spog/ui/Cargo.toml, etc)

```json
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

You can use the following command to get all the Cargo.toml files to copy and paste:

```shell
find . -type f -name "Cargo.toml" | sed 's|^\./||' | sed 's|^|\"|' | sed 's|$|\",|'
```

<details>
<summary>Result</summary>

```json
"admin/Cargo.toml",
"analytics/Cargo.toml",
"api/Cargo.toml",
"auth/Cargo.toml",
"bombastic/api/Cargo.toml",
"bombastic/bombastic/Cargo.toml",
"bombastic/index/Cargo.toml",
"bombastic/indexer/Cargo.toml",
"bombastic/model/Cargo.toml",
"bombastic/walker/Cargo.toml",
"collector/client/Cargo.toml",
"collector/collector/Cargo.toml",
"collector/osv/Cargo.toml",
"collector/snyk/Cargo.toml",
"collectorist/api/Cargo.toml",
"collectorist/client/Cargo.toml",
"collectorist/collectorist/Cargo.toml",
"common/Cargo.toml",
"common/walker/Cargo.toml",
"event-bus/Cargo.toml",
"exhort/api/Cargo.toml",
"exhort/exhort/Cargo.toml",
"exhort/model/Cargo.toml",
"exporter/Cargo.toml",
"index/Cargo.toml",
"indexer/Cargo.toml",
"infrastructure/Cargo.toml",
"integration-tests/Cargo.toml",
"reservoir/api/Cargo.toml",
"reservoir/reservoir/Cargo.toml",
"spog/api/Cargo.toml",
"spog/model/Cargo.toml",
"spog/spog/Cargo.toml",
"spog/ui/crates/backend/Cargo.toml",
"spog/ui/crates/common/Cargo.toml",
"spog/ui/crates/components/Cargo.toml",
"spog/ui/crates/donut/Cargo.toml",
"spog/ui/crates/navigation/Cargo.toml",
"spog/ui/crates/utils/Cargo.toml",
"spog/ui/Cargo.toml",
"storage/Cargo.toml",
"trust/Cargo.toml",
"v11y/api/Cargo.toml",
"v11y/client/Cargo.toml",
"v11y/index/Cargo.toml",
"v11y/indexer/Cargo.toml",
"v11y/model/Cargo.toml",
"v11y/v11y/Cargo.toml",
"v11y/walker/Cargo.toml",
"version/Cargo.toml",
"vexination/api/Cargo.toml",
"vexination/index/Cargo.toml",
"vexination/indexer/Cargo.toml",
"vexination/model/Cargo.toml",
"vexination/vexination/Cargo.toml",
"vexination/walker/Cargo.toml",
"xtask/Cargo.toml",
"Cargo.toml",
```

</details>

## Debug code within VSCode

The following extension must be installed in order to debug Rust code on VSCode :

- On Linux use [CodeLLDB](https://marketplace.visualstudio.com/items?itemName=vadimcn.vscode-lldb) extension
- On Windows use [Microsoft C++](https://marketplace.visualstudio.com/items?itemName=vadimcn.vscode-lldb) extension.

The [Rust Analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer) extension provides the Rust Language Server and also pilots the debugger.

See <https://code.visualstudio.com/docs/languages/rust> for details.

You can add a debugging entry in the `./vscode/launch.json` file, for example:

```json
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

Another example, for running the Vexination walker:

```json
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
