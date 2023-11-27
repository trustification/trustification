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
    OPTSTR="s:thb:d:"
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
            d) # Set test data
                CARGO_PATH=$OPTARG
                setup_data
            ;;
            *)
                echo "Invalid Input"
                help_context $OPTSTR
                exit 1
        esac
    done

}

help_context(){
    echo "Possible inputs: -s -t -h -d"
    echo "Explanation of inputs "
    echo "      -s: Setup webdriver"
    echo "      -t: Teardown webdriver"
    echo "      -b: Browser [default to chrome]"
    echo "      -h: Help menu"
    echo "      -d: Load test data to localhost"
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

setup_data(){
    $CARGO_PATH run -p trust -- vexination walker --devmode -3 --sink http://localhost:8081/api/v1/vex --source ../data/ds1/csaf
    $CARGO_PATH run -p trust -- bombastic walker --devmode -3 --sink http://localhost:8082/api/v1/sbom --source ../data/ds1/sbom
    sleep 30
}

argument_parser "$@"

set +e