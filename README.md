# financial_tracker_api



### Quick Start

- You have the option to use .env file or export each variable alone.
```bash
export POSTGRES_USER=<value>
export POSTGRES_PASSWORD=<value>
export POSTGRES_DB=<value>
export POSTGRES_HOST=<value>
export JWT_SECRET=<value>
export PORT=<value>
```

```bash
go build -o srv cmd/main.go
```

```bash
./srv
```

***Run With Docker***

- in Docker we are not using .env file.
```bash
docker-compose up --build -d
docker compose up -d db
```

***unit testing***

TODO: run the unit testing with sqlmock but that will be in next versions, depends on niat =)

- in unit testing you have two options of setting the environment variables:

1. using .env and in this case you will use the following command to test.
```bash
go test -v -coverprofile cover.out ./pkg/handler/... -c
```
```bash
./handler.test
```

2. Or when setting up the environment variables one by one or you can use shell
   file if you are in linux and `source <file>.sh` you will need to execute the
   following command.
```bash
go test -v -coverprofile cover.out ./pkg/handler/...
```

- to check coverage you need to execute the following command.
```bash
go tool cover -html=cover.out
```
it will open your default browser with the details of the coverage.

***swagger***

The swagger documentation is running on the following path, or can look system design and personal notes on https://docs.google.com/document/d/1vJUO4M3DfpMecukJHp68LP7W_MvPcALDBYeIIqPQKIg/edit?usp=sharing

```http
http://localhost:8080/api/v1/swagger/index.html
```
