FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY . .
RUN dotnet restore ./SecureToolKitAPI/SecureToolKitAPI.csproj

RUN dotnet publish ./SecureToolKitAPI/SecureToolKitAPI.csproj \
    --configuration Release \
    --no-restore \
    --output /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final

WORKDIR /app

COPY --from=build /app/publish /app

ENTRYPOINT ["dotnet", "SecureToolKitAPI.dll"]
