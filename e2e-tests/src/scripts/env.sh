#! /bin/sh
set -e
#----------- Global Variables---------
CARGO_PATH=""
DRIVER_PATH="./driver"
BROWSER="chrome"

if [ $# -lt 1 ]; then
    echo "Cargo path not supplied"
    echo "Usage: $0 <Path to cargo>"
    exit 1
fi


argument_parser() {
    ARGS=$@
    OPTSTR="s:thb:"
    while getopts $OPTSTR flag; do
        case "$flag" in
            s) # Setup browser driver
                CARGO_PATH=$OPTARG
                setup_env
            ;;
            b) # Browser to run scripts
                BROWSER=$OPTARG
            ;;
            t) # Teardown driver
                teardown_env
            ;;
            h) # Override variable file
                echo "Invalid Input"
                help_context $OPTSTR
                exit 1
            ;;
            *)
                echo "Invalid Input"
                help_context $OPTSTR
                exit 1
        esac
    done

}

help_context(){
    echo "Possible inputs: -s -t -h"
    echo "Explanation of inputs "
    echo "      -s: Setup webdriver"
    echo "      -t: Teardown webdriver"
    echo "      -b: Browser [default to chrome]"
    echo "      -h: Help menu"
}

setup_env(){
    mkdir -p $DRIVER_PATH
    chmod +x $DRIVER_PATH
    $CARGO_PATH install --git https://github.com/SeleniumHQ/selenium --branch trunk > /dev/null 2>&1

    if [ $? -ne 0 ]; then
        echo "Error while installing selenium manager"
    fi

    INFO=$(selenium-manager --browser $BROWSER  --cache-path $DRIVER_PATH 2>&1)
    if [[ $INFO == *"Driver path"* ]]; then
        DRIVER_PATH=$(echo "$INFO" | grep "Driver path" | sed -e 's/^.* \(.*\)$/\1/')
    fi
    echo $DRIVER_PATH
}

teardown_env(){
    pkill -f $DRIVER_PATH
    DRIVER_PATH="./driver"
    rm -rf ./driver
}


argument_parser "$@"

set +e
