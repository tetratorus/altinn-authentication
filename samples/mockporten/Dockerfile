FROM mcr.microsoft.com/dotnet/sdk:9.0-alpine AS build
WORKDIR /app

COPY Mockporten ./Mockporten
RUN dotnet publish ./Mockporten/Mockporten.csproj -c Release -o app_output --no-self-contained

FROM mcr.microsoft.com/dotnet/aspnet:9.0-alpine AS final
EXPOSE 5090
ENV ASPNETCORE_HTTP_PORTS=5090
WORKDIR /app
COPY --from=build /app/app_output .

RUN addgroup -g 3000 dotnet && adduser -u 1000 -G dotnet -D -s /bin/false dotnet
USER dotnet

ENTRYPOINT ["dotnet", "Mockporten.dll"]
