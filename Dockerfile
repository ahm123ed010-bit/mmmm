FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY Moarekh.csproj .
RUN dotnet restore
COPY . .
RUN dotnet publish -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app .

RUN mkdir -p /data/storage && chmod -R 777 /data
ENV STORAGE_PATH=/data/storage
ENV PORT=7860
EXPOSE 7860
EXPOSE 8080

ENTRYPOINT ["dotnet", "Moarekh.dll"]
