#!/usr/bin/env bash

set -e

if [ $TRAVIS_OS_NAME = "osx" ]; then
  ulimit -n 1024
  dotnet restore --disable-parallel --runtime osx-x64
else
  dotnet restore --runtime ubuntu-x64
fi

export FrameworkPathOverride=$(dirname $(which mono))/../lib/mono/4.5/

dotnet test ./test/LibP2P.Peer.Tests/LibP2P.Peer.Tests.csproj -c Release -f netcoreapp1.1

# disabled net461 for now as sodium.core does not work with net461, yet
#dotnet build ./test/LibP2P.Crypto.Tests/LibP2P.Crypto.Tests.csproj -c Release -f net461
#mono $HOME/.nuget/packages/xunit.runner.console/2.2.0/tools/xunit.console.exe ./test/LibP2P.Crypto.Tests/bin/Release/net461/LibP2P.Crypto.Tests.dll
