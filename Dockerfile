# `python-base` sets up all our shared environment variables
FROM python:3.10.13-alpine as python-base

    # python
ENV PYTHONUNBUFFERED=1 \
    # prevents python creating .pyc files
    PYTHONDONTWRITEBYTECODE=1 \
    \
    # pip
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    \
    # poetry
    # https://python-poetry.org/docs/configuration/#using-environment-variables
    POETRY_VERSION=1.6.1 \
    # make poetry install to this location
    POETRY_HOME="/opt/poetry" \
    # make poetry create the virtual environment in the project's root
    # it gets named `.venv`
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    # do not ask any interactive question
    POETRY_NO_INTERACTION=1 \
    \
    # paths
    # this is where our requirements + virtual environment will live
    PYSETUP_PATH="/opt/pysetup" \
    VENV_PATH="/opt/pysetup/.venv"

# prepend poetry and venv to path
ENV PATH="$POETRY_HOME/bin:$VENV_PATH/bin:/root/.cargo/bin:$PATH"


# `builder-base` stage is used to build deps + create our virtual environment
FROM python-base as builder-base

RUN apk add --no-cache g++ make curl libpq-dev postgresql-client libffi-dev gcc musl-dev
RUN curl https://sh.rustup.rs -sSf | \
    sh -s -- --default-toolchain=1.60.0 stable -y

# install poetry - respects $POETRY_VERSION & $POETRY_HOME
RUN curl -sSL https://install.python-poetry.org | python -

# copy project requirement files here to ensure they will be cached.
WORKDIR $PYSETUP_PATH
COPY poetry.lock pyproject.toml ./

# install runtime deps - uses $POETRY_VIRTUALENVS_IN_PROJECT internally
RUN poetry install --only main


# `production` image used for runtime
FROM python-base as production

USER nobody:nobody

# Copy dependencies from build container
WORKDIR /app
COPY --from=builder-base $PYSETUP_PATH $PYSETUP_PATH
COPY --from=builder-base /usr/lib/ /usr/lib/

# Copy source code
COPY . ./

# set env
ENV PYTHONPATH="${PYTHONPATH}:/app"

# Start application
ENTRYPOINT ["python"]
CMD ["src/main.py"]
