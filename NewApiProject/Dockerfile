FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

COPY ["NewApiProject/NewApiProject.csproj", "NewApiProject/"]
RUN dotnet restore "NewApiProject/NewApiProject.csproj"

COPY . .
WORKDIR "/src/NewApiProject"
RUN dotnet publish "NewApiProject.csproj" -c Release -o /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS final
WORKDIR /app
COPY --from=build /app/publish .

ENTRYPOINT ["dotnet", "NewApiProject.dll"]