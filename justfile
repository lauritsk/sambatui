set positional-arguments

build *args:
    docker build -t sambatui:local "$@" .
    docker run --rm -i -v /config --entrypoint python sambatui:local - < tests/runtime.py

run *args:
    docker run --rm -it -v sambatui-config:/config "$@" sambatui:local

test *args:
    docker build --target dev -t sambatui:dev .
    docker run --rm --entrypoint python sambatui:dev -m pytest "$@"

lint:
    docker build --target dev -t sambatui:dev .
    docker run --rm --entrypoint sh sambatui:dev -c 'uvx ruff check . && uvx ruff format --check .'
