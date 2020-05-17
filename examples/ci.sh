#!/bin/bash
set -e

# this example needs jq besides psoco
# most distros include jq in their package manger (if not see https://stedolan.github.io/jq/download/)
REQUIRED_COMMANDS=(
    "psoco"
    "jq"
)

# use psoco search to get the UUID of the secret you need for your CI
# let's say this secret contains your docker registry login data
SECRET_UUID="db4c3f08-fd46-4f3f-8d9b-de0987070694"

# In this example $PSOCO_CONFIG_PATH contains the path to your config set by the CI tool
# e.g. set via Gitlab as CI/CD Variable with type file
EXTERNAL_REQUIRED_VARS=(
    "PSOCO_CONFIG_PATH"
)

# check for required commands
for command in ${REQUIRED_COMMANDS[*]}; do
    if ! [ -x "$(command -v "$command")" ]; then
        echo "ERROR: $command is not installed" >&2;
        exit 1
    fi
done

# always check for all external environment variables and fail early so you
# don't waste time with unset env vars
for val in ${EXTERNAL_REQUIRED_VARS[*]}; do
    if [ -z "${!val}" ]; then
        echo "ERROR: ${val} is unset or empty" >&2;
        exit 1
    fi
done

# load all your secrets data into a variable
SECRET_CONTENTS=$(psoco --config-path "$PSOCO_CONFIG_PATH" all --json "$SECRET_UUID")

# now extract all secrets to seperate variables with jq (-r for raw output, otherwise strings would be quoted)
USERNAME=$(echo "$SECRET_CONTENTS" | jq -r .username)
PASSWORD=$(echo "$SECRET_CONTENTS" | jq -r .password)
URL=$(echo "$SECRET_CONTENTS" | jq -r .url)

# login into docker registry
echo "${PASSWORD}" | docker login --username="${USERNAME}" --password-stdin "${URL}"
