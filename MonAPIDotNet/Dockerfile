# Use multi-stage build for better image size
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy csproj and restore as distinct layers
COPY ["MonAPIDotNet.csproj", "./"]
RUN dotnet restore "./MonAPIDotNet.csproj"

# Copy the rest of the files and build
COPY . .
WORKDIR "/src/."
RUN dotnet build "MonAPIDotNet.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "MonAPIDotNet.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Final runtime image
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "MonAPIDotNet.dll"]
