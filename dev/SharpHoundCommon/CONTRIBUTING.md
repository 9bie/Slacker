# SharpHoundCommon Contributing Guide

## Prerequisites

### Tools

- [.NET SDK](https://docs.microsoft.com/en-us/dotnet/core/install/)

## Build

``` powershell
dotnet build
```

## Unit Test

This project is configured to generate test coverage every time tests are run and produces a HTML report at
[./docfx/coverage/report](./docfx/coverage/report).


``` powershell
dotnet test
```

## Documentation

Documentation is generated into Html from Markdown using [docfx](https://https://dotnet.github.io/docfx/).

To build the docs:

``` powershell
dotnet build docfx
```

To preview the docs:

``` powershell
dotnet build docfx
dotnet build docfx -t:Serve
```

To preview the docs with test coverage:

``` powershell
dotnet test
dotnet build docfx
dotnet build docfx -t:Serve
```
