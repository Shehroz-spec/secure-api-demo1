FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

COPY ["NewApiProject.csproj", "./"]
RUN dotnet restore "NewApiProject.csproj"

COPY . .
RUN dotnet build "NewApiProject.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "NewApiProject.csproj" -c Release -o /app/publish \
    --no-restore \
    /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS final
WORKDIR /app

COPY --from=publish /app/publish .

EXPOSE 8080
ENV ASPNETCORE_ENVIRONMENT=Production
ENV ASPNETCORE_URLS=http://+:8080

ENTRYPOINT ["dotnet", "NewApiProject.dll"]